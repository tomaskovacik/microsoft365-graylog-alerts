<#
.SYNOPSIS
    Export who may read which mailbox, as the CSV the Graylog lookup table
    `o365-delegates` reads.

.DESCRIPTION
    The alert "O365 - new delegate reading a mailbox" fires when someone reads a
    mailbox that is not their own (MailItemsAccessed, LogonType 2) and the pair
    "<reader>><mailbox>" is not in the `o365-delegates` lookup table. This script
    seeds that table from what actually grants such access:

      * FullAccess on shared mailboxes (and, with -IncludeUserMailboxes, on user
        mailboxes, e.g. an assistant reading a manager's mail). Permissions
        granted to a mail-enabled security group are expanded to its members.
      * Membership of Microsoft 365 / Teams groups, whose members read the
        group's inbox as delegates.

    Read-only: it only runs Get-* cmdlets. Signs in interactively through the
    browser (or with a device code, -Device), so no app registration, secret
    or certificate is needed. Needs an account that can read recipients and
    mailbox permissions, e.g. Global Reader or View-Only Organization
    Management.

    Microsoft Graph cannot do this: it does not expose mailbox permissions,
    which is why this uses Exchange Online PowerShell.

    Output columns: "pair","source", pair = reader>mailbox in lower case,
    source = shared-fullaccess | user-fullaccess | m365-group.

.PARAMETER OutFile
    Defaults to o365_delegates_export.csv. Copy it next to the lookup CSV on the
    Graylog host (see README, "Delegate mailbox access").

.PARAMETER Device
    Device-code sign-in instead of opening a browser (headless / SSH sessions).

.EXAMPLE
    pwsh ./Export-O365Delegates.ps1
    pwsh ./Export-O365Delegates.ps1 -IncludeUserMailboxes -OutFile delegates.csv
#>
[CmdletBinding()]
param(
    [string]$OutFile = "o365_delegates_export.csv",
    [string]$UserPrincipalName,
    [switch]$Device,
    [switch]$IncludeUserMailboxes
)
$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "Installing ExchangeOnlineManagement for the current user..."
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement

$connect = @{ ShowBanner = $false }
if ($UserPrincipalName) { $connect.UserPrincipalName = $UserPrincipalName }
if ($Device) { $connect.Device = $true }
Connect-ExchangeOnline @connect

$pairs = @{}   # pair -> set of sources
function Add-Pair([string]$user, [string]$mailbox, [string]$source) {
    $u = "$user".Trim().ToLower(); $m = "$mailbox".Trim().ToLower()
    if ($u -notlike "*@*" -or $m -notlike "*@*" -or $u -eq $m) { return }
    $key = "$u>$m"
    if (-not $pairs.ContainsKey($key)) { $pairs[$key] = [System.Collections.Generic.HashSet[string]]::new() }
    [void]$pairs[$key].Add($source)
}

# A FullAccess trustee is either a user (UPN) or a group (display name). Groups
# are expanded one level to their members' addresses; unknown names are skipped.
$groupCache = @{}
function Resolve-Trustee([string]$trustee) {
    if ($trustee -like "*@*") { return @($trustee) }
    if ($groupCache.ContainsKey($trustee)) { return $groupCache[$trustee] }
    $members = @()
    try {
        $r = Get-Recipient -Identity $trustee -ErrorAction Stop
        if ($r.RecipientTypeDetails -match "Group") {
            $members = Get-DistributionGroupMember -Identity $r.Identity -ResultSize Unlimited |
                Where-Object { $_.PrimarySmtpAddress } |
                ForEach-Object { "$($_.PrimarySmtpAddress)" }
        }
    } catch { }
    $groupCache[$trustee] = $members
    return $members
}

try {
    $types = @("SharedMailbox")
    if ($IncludeUserMailboxes) { $types += "UserMailbox" }
    foreach ($type in $types) {
        $source = if ($type -eq "SharedMailbox") { "shared-fullaccess" } else { "user-fullaccess" }
        $mailboxes = @(Get-EXOMailbox -RecipientTypeDetails $type -ResultSize Unlimited -Properties UserPrincipalName)
        Write-Host "$($mailboxes.Count) $type mailboxes"
        foreach ($mb in $mailboxes) {
            Get-EXOMailboxPermission -Identity $mb.UserPrincipalName |
                Where-Object { $_.AccessRights -contains "FullAccess" -and -not $_.IsInherited -and
                               $_.User -notmatch "^(NT AUTHORITY|S-1-5-)" } |
                ForEach-Object {
                    foreach ($u in Resolve-Trustee $_.User) { Add-Pair $u $mb.UserPrincipalName $source }
                }
        }
    }

    $groups = @(Get-UnifiedGroup -ResultSize Unlimited)
    Write-Host "$($groups.Count) Microsoft 365 / Teams groups"
    foreach ($g in $groups) {
        Get-UnifiedGroupLinks -Identity $g.Identity -LinkType Members -ResultSize Unlimited |
            ForEach-Object { Add-Pair $_.PrimarySmtpAddress $g.PrimarySmtpAddress "m365-group" }
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

if ($pairs.Count -eq 0) {
    throw "No pairs found - not writing an empty allowlist (every delegate read would alert)."
}
$pairs.Keys | Sort-Object | ForEach-Object {
    [pscustomobject]@{ pair = $_; source = (($pairs[$_] | Sort-Object) -join "+") }
} | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
Write-Host "$($pairs.Count) pairs written to $OutFile"
