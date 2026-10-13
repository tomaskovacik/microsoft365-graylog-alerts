#!/usr/bin/env python3
"""Desired state for the Office 365 alert set. Creates or updates by title.

Two fixes over v1, both found by replaying the queries against 90 days of real data:
  * "OAuth admin permission granted" looked for Operation:"Add OAuth2PermissionGrant.",
    which this tenant never emits (0/90d). The real operation is
    "Add app role assignment to service principal." - application permissions
    granted to a service principal, 22/90d, including full_access_as_app.
  * The sharing alert missed AddedToSharingLink (16/90d).

And one fix that applies to every definition: timestamp == CreationTime, so the
aggregation window is measured in EVENT time while records arrive a median 5.3
minutes late (p95 9.4, max 14.0). A 5-minute window evaluated every 5 minutes
gives a record ~2.5 minutes to arrive, so most events landed in a window that
had already been evaluated and were never seen. Window is now 30 minutes,
still evaluated every 5, so each event is covered by 6 overlapping runs. The
grace period is raised to match the window, so the overlap still sends one mail.
"""
import json

from config import STREAMS, MAIL, HOME_CC, USER_HOME_CC, ALLOWED_CC

WINDOW_MS = 1_800_000   # 30 min, > max observed ingest lag with headroom
EVERY_MS = 300_000      # 5 min, matches collection interval
GRACE_MS = 1_800_000    # one mail per key per window

# A trip produces logins all day (rak: 117 in one day), and a 30-minute grace
# would mail about each half hour of it. For the geo rules one mail per person
# per country per day is what is actually wanted.
# Alerts that fire on a COUNT, not on existence. Measured, not guessed.
THRESHOLD_PER_ALERT = {
    # worst legitimate case in 90d was 15 bad passwords in 30 min by a real
    # user, p95 is 5. A threshold of 10 fires about once a quarter.
    "O365 - repeated bad password for one account": 10.0,
}

GRACE_PER_ALERT = {
    "O365 - login from unexpected country": 86_400_000,
    "O365 - login from outside EU/EEA": 86_400_000,
}

# EU, plus the rest of the EEA (IS/LI/NO), CH and GB. Liechtenstein is in here
# because 60 of 64 non-EU logins in 90d were one user via an LI exit node.
# Drop IS/LI/NO/CH/GB from this list for strict EU-only.
GEO_Q = ('Operation:UserLoggedIn AND _exists_:ClientIP_country_code '
         'AND NOT ClientIP_country_code:(' + ' OR '.join(ALLOWED_CC) + ')')

# ---------------------------------------------------------------------------
# Tighter geo rule: every login is expected from Slovakia, with named per-user
# exceptions. Edit this dict and re-run `sync_alerts.py --apply`.
# Counts are logins observed in the 90 days to 2026-10-12.
# ---------------------------------------------------------------------------

# Some UserLoggedIn records carry a GUID instead of a UPN: they are intermediate
# strong-auth steps emitted alongside the real user's record in the same flow
# (observed in production, where a GUID actor accompanied a real user's own
# sign-ins in the same authentication flow).
# They name nobody, so they only produce an unactionable second mail. Excluding
# them removed exactly 1 hit from 273 over 90 days and suppressed no real alert.
NOT_A_GUID_ACTOR = ('NOT UserId:/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
                    '-[0-9a-f]{4}-[0-9a-f]{12}/')

# The real list lives in config.py. The SHAPE is the useful part: a few people
# permanently abroad, one shared client VPN that appears as a single country
# for several people, and partner-company accounts.
#
# Resolve the network owner of every address (ipinfo or similar) before
# trusting an entry. In the tenant this came from, one user who looked
# "based in CZ" was 96% a rentable commercial VPN range - meaning the geo
# rules cannot protect that account at all, which is worth knowing explicitly
# rather than assuming coverage.
#
#   USER_HOME_CC = {
#       "based.abroad1@example.com": ["EE"],  # real ISP, genuinely resident
#       "vpn.user1@example.com": ["BE"],      # client VPN - same AS as next two
#       "vpn.user2@example.com": ["BE"],
#       "vpn.user3@example.com": ["BE"],
#       "traveller@example.com": ["LI", "AT", "CH"],
#       "partner1@example.org": ["CZ"],       # partner company, real ISPs
#   }
# Four entries were removed from the original list once the owner identified
# them as holidays rather than home countries - a trip is exactly what this
# rule should surface, so excluding it defeats the point. Check each candidate
# with the owner before adding it; volume alone does not distinguish "lives
# there" from "spent a fortnight there".


def _unexpected_country_query():
    # UserType 4 is excluded: those are "Not Available" system logins with no
    # user identity, so no per-user exception can be written for them. All 450
    # in 90d came from SK and EE.
    parts = ["Operation:UserLoggedIn",
             "_exists_:ClientIP_country_code",
             "NOT UserType:4",
             NOT_A_GUID_ACTOR,
             f"NOT ClientIP_country_code:{HOME_CC}"]
    for user, ccs in USER_HOME_CC.items():
        cc = ccs[0] if len(ccs) == 1 else "(" + " OR ".join(ccs) + ")"
        parts.append(f'NOT (UserId:"{user}" AND ClientIP_country_code:{cc})')
    return " AND ".join(parts)


UNEXPECTED_CC_Q = _unexpected_country_query()
GEO_Q = GEO_Q + " AND NOT UserType:4 AND " + NOT_A_GUID_ACTOR

MS_EXCHANGE_SVC = ("NT SERVICE\\\\MSExchangeAdminApiNetCore "
                   "(Microsoft.Exchange.AdminApi.NetCore)")

# title, query, priority, group_by, note
ALERTS = [
    ("O365 - transport rule changed",
     'Operation:("New-TransportRule" OR "Set-TransportRule" OR "Remove-TransportRule")',
     3, ["UserId"], "0/90d - mail flow rules can silently copy or divert all mail"),

    ("O365 - mailbox audit bypass configured",
     'Operation:"Set-MailboxAuditBypassAssociation"',
     3, ["UserId"], "0/90d - stops a mailbox being audited at all"),

    ("O365 - mailbox export requested",
     'Operation:("New-MailboxExportRequest" OR "New-ComplianceSearchAction" '
     'OR "New-ComplianceSearch")',
     3, ["UserId"], "0/90d - bulk extraction of a mailbox to file. "
                    "New-MailboxExportRequest is hybrid-only and cannot occur "
                    "on a cloud-only tenant; the Compliance pair is the "
                    "cloud path"),

    ("O365 - directory role assigned",
     'Operation:("Add member to role." OR "Add eligible member to role.")',
     3, ["UserId"], "0/90d - privilege escalation. Naming confirmed by "
                    "'Add member to group.' (307/90d) using the same pattern"),

    ("O365 - user password reset by admin",
     'Operation:"Reset user password."',
     2, ["UserId"], "20/90d by a single admin, clustered in one fortnight - "
                    "query proven against real admin activity"),

    ("O365 - OAuth admin permission granted",
     'Operation:"Add app role assignment to service principal."',
     3, ["UserId"], "22/90d - application permissions granted to a service "
                    "principal; observed grants include full_access_as_app"),

    ("O365 - anonymous sharing link created",
     'Operation:("AnonymousLinkCreated" OR "SharingInvitationCreated" '
     'OR "AddedToSecureLink" OR "AddedToSharingLink")',
     2, ["UserId"], "41/90d"),

    ("O365 - inbox rule created or modified",
     'Operation:("New-InboxRule" OR "Set-InboxRule")',
     2, ["UserId"], "25/90d - classic BEC persistence"),

    ("O365 - admin audit configuration changed",
     f'Operation:"Set-AdminAuditLogConfig" AND NOT UserId:"{MS_EXCHANGE_SVC}"',
     3, ["UserId"], "51/90d unfiltered, 0 after excluding MSExchangeAdminApiNetCore "
                    "- exclusion verified to be what silences it"),

    # --- new ---
    ("O365 - Entra app registration created",
     'Operation:"Add application."',
     2, ["UserId"], "36/90d. 'Add service principal.' (60/90d) is deliberately "
                    "not included: it also fires when a first-party app is first used"),

    # Only matchable on the GELF stream: the collector flattens ModifiedProperties
    # into real fields, so ConsentContext.IsAdminConsent becomes searchable.
    # The plaintext copy of the same record lacks the field and therefore cannot
    # match, which also means this alert goes blind if the GELF feed stops.
    ("O365 - admin consent granted to application",
     'Operation:"Consent to application." '
     'AND ConsentContext_IsAdminConsent_NewValue:True',
     3, ["UserId"], "9/90d admin vs 3/90d ordinary user consent. Unfiltered "
                    "'Consent to application.' is 127/90d and mostly user consent"),

    # MFA tampering. Entra's own "User deleted security info" events do NOT reach
    # the Management API at all (0/90d for every variant) - they surface only as
    # Operation:"Update user." carrying the StrongAuthenticationPhoneAppDetail
    # properties, and only on the GELF stream, where ModifiedProperties is
    # flattened. Grouped by ObjectId, not UserId: the actor on these records is
    # always Azure's own MFA service principal, so UserId names nobody useful -
    # ObjectId is the person whose MFA actually changed.
    # Add vs remove is visible in _NewValue_count vs _OldValue_count, which a
    # Lucene query cannot compare, so this fires on any change either way.
    ("O365 - MFA method changed",
     'Operation:"Update user." '
     'AND _exists_:StrongAuthenticationPhoneAppDetail_NewValue_Id',
     3, ["ObjectId"], "13/90d across 4 users. Goes blind if the GELF collector "
                      "stops, since plaintext cannot express this query"),

    # Microsoft's own Purview alert policies land in the audit feed as
    # RecordType 40. These are the DEFAULT policies, included without Defender
    # P2 - proven by 12 "Creation of forwarding/redirect rule" alerts in 90d on
    # this tenant. Alerting on "any Microsoft alert except the known-noisy ones"
    # is licence-agnostic: new policies start alerting automatically if the
    # tenant is ever upgraded, with no change here.
    #
    # Severity is NOT a usable filter - the forwarding-rule policy is
    # "Informational". Grouped by Name (the policy) because UserId is always
    # the literal string "SecurityComplianceAlerts"; the affected user is in
    # ObjectId on AlertEntityGenerated records and inside the Data JSON blob.
    ("O365 - Microsoft security alert raised",
     'RecordType:40 AND NOT Name:("Email reported by user as not junk" '
     'OR "Email reported by user as malware or phish" '
     'OR "Email reported by user as junk")',
     3, ["Name"], "12/90d, all 'Creation of forwarding/redirect rule'. The three "
                  "excluded policies are user-reported email (90/90d) and carry "
                  "no attacker signal"),

    # Mail forwarding, both vectors. GELF-only: the collector flattens cmdlet
    # Parameters into real fields, which plaintext cannot express.
    #
    # Deliberately NOT filtered to external recipients only. Microsoft's own
    # "Creation of forwarding/redirect rule" policy fired 12 times in 90d here,
    # every one a rule forwarding to an internal colleague - correct detection,
    # but it cannot tell internal from external. An internal/external regex
    # would fix that, and was rejected: the whole population is 4 rules per
    # 90 days, so the "noise" it would remove is ~1 mail a month, while a regex
    # that silently fails to match is the one failure mode a security alert
    # must not have.
    #
    # Set-Mailbox forwarding is the vector Microsoft's rule policy does NOT
    # cover: it forwards everything at the mailbox level, no inbox rule needed.
    ("O365 - mail forwarding configured",
     '(Operation:("New-InboxRule" OR "Set-InboxRule" OR "UpdateInboxRules") '
     'AND (_exists_:ForwardTo OR _exists_:RedirectTo '
     'OR _exists_:ForwardAsAttachmentTo)) '
     'OR (Operation:"Set-Mailbox" AND (_exists_:ForwardingSmtpAddress '
     'OR _exists_:ForwardingAddress))',
     3, ["UserId"], "4 inbox-rule forwards in 90d (all internal), 0 mailbox-level. "
                    "UNVERIFIED: no forwarding rule exists inside the GELF window "
                    "yet, so the field names are inferred from the flattening of "
                    "MoveToFolder/From/Name. Confirm with a throwaway rule"),

    # --- from the Wazuh/ELK comparison, validated against this tenant ---

    # 26 distinct in 90d. How an attacker persists inside an app you already
    # trust, which the app-registration alert does not cover.
    ("O365 - app credentials added",
     'Operation:"Update application – Certificates and secrets management"',
     3, ["UserId"], "26 distinct in 90d (154 raw, inflated by a collector "
                    "duplication bug), all by one admin. ~0.3/day"),

    # 14 distinct in 90d, 12 of them by Exchange's own service account doing
    # routine provisioning - excluded by exact full value, since a wildcard
    # inside a quoted phrase matches literally and excludes nothing.
    ("O365 - mailbox delegation granted",
     'Operation:("Add-MailboxPermission" OR "Add-RecipientPermission") '
     f'AND NOT UserId:"{MS_EXCHANGE_SVC}"',
     3, ["UserId"], "~3 human-initiated in 90d. FullAccess and SendAs are how a "
                    "mailbox is read without touching its password"),

    # Outlook logs rule changes as UpdateInboxRules rather than New-InboxRule,
    # so the main inbox-rule alert misses them entirely. Kept as its own
    # definition so it can be muted without silencing that cleaner alert.
    ("O365 - inbox rules changed from Outlook client",
     'Operation:"UpdateInboxRules"',
     1, ["UserId"], "72 distinct in 90d (356 raw) = ~0.8/day. Chattier than "
                    "New-InboxRule because it covers ordinary mail filing"),

    # Thresholds measured, not guessed. UserLoginFailed alone is useless here:
    # legitimate users hit 64 in a 30-minute window because MFA interrupts are
    # logged as failures. Restricted to genuine bad passwords, the worst real
    # user managed 15, p95 is 5.
    ("O365 - repeated bad password for one account",
     'Operation:UserLoginFailed AND LogonError:InvalidUserNameOrPassword',
     3, ["UserId"], "threshold >10 per 30min; worst legitimate case in 90d was "
                    "15, so this fires about once a quarter"),

    # A failed sign-in from an unexpected country never reaches the geo rules,
    # which only watch successful UserLoggedIn. 2 hits in 90d: India, Russia.
    ("O365 - bad password attempt from outside EU/EEA",
     'Operation:UserLoginFailed AND LogonError:InvalidUserNameOrPassword '
     'AND _exists_:ClientIP_country_code '
     'AND NOT ClientIP_country_code:(' + ' OR '.join(ALLOWED_CC) + ')',
     3, ["UserId", "ClientIP_country_code"],
     "2 in 90d (IN, RU). Invisible to the geo alerts, which require a "
     "successful login"),

    # --- Near-zero, high-impact. NOTE ON CONFIDENCE ---
    # None of these have ever occurred here, so their operation names cannot be
    # confirmed from data. They are not equally risky guesses:
    #
    #   Exchange cmdlets (*-ProtectionAlert, Set-*Policy, Set-RemoteDomain) are
    #   SAFE: proven on this tenant that RecordType 1 logs the literal cmdlet
    #   name, across 23 distinct values plus three live tests.
    #
    #   Entra friendly strings ("Set domain authentication." and friends) are
    #   the RISKY class - exactly the format where "Add OAuth2PermissionGrant."
    #   turned out never to be emitted here. Treat these as unproven until one
    #   fires or is tested.

    ("O365 - domain or federation changed",
     'Operation:("Set domain authentication." '
     'OR "Set federation settings on domain." '
     'OR "Add domain to company." OR "Remove domain from company." '
     'OR "Verify domain.")',
     3, ["UserId"], "0/90d. UNPROVEN NAMES (Entra friendly-string format). "
                    "Federation takeover is a full-tenant compromise"),

    ("O365 - Microsoft alert policy tampered with",
     'Operation:("Disable-ProtectionAlert" OR "Remove-ProtectionAlert" '
     'OR "Set-ProtectionAlert" OR "New-ProtectionAlert")',
     3, ["UserId"], "New-ProtectionAlert CONFIRMED by 4 records on 2026-10-13 "
                    "20:00 when the tenant owner created policies in the "
                    "portal; the other three names follow the same proven "
                    "Exchange cmdlet rule. Matters because Microsoft's own "
                    "policies are now a detection layer: disabling them "
                    "creates a blind spot, the same move as mailbox audit "
                    "bypass"),

    ("O365 - mail security policy weakened",
     'Operation:("Set-AntiPhishPolicy" OR "Set-MalwareFilterPolicy" '
     'OR "Set-HostedContentFilterPolicy" '
     'OR "Set-HostedOutboundSpamFilterPolicy" OR "Set-RemoteDomain" '
     'OR "Remove-AntiPhishPolicy" OR "Remove-MalwareFilterPolicy")',
     3, ["UserId"], "0/90d. Names follow the proven Exchange cmdlet rule. "
                    "Set-RemoteDomain is how tenant-wide auto-forwarding gets "
                    "re-enabled"),

    ("O365 - user account created",
     'Operation:"Add user."',
     2, ["UserId"], "17/90d"),

    ("O365 - group created",
     'Operation:("Add group." OR "New-UnifiedGroup" OR "New-DistributionGroup")',
     1, ["UserId"], "45/90d"),

    # Tighter companion to the EU/EEA rule below: Slovakia plus named per-user
    # exceptions. Grouped by user AND country so each trip is its own alert
    # rather than one per login.
    ("O365 - login from unexpected country",
     UNEXPECTED_CC_Q,
     2, ["UserId", "ClientIP_country_code"],
     "18 logins in 90d resolving to 8 distinct trips, about one mail every "
     "11 days"),

    ("O365 - login from outside EU/EEA",
     GEO_Q,
     2, ["UserId", "ClientIP_country_code"],
     "4/90d with this allowlist (LK x2, AE, TR). Strict EU-only would add 60 "
     "hits from one user behind an LI exit node. _exists_ guard is required: "
     "without it a record missing the geoip field satisfies the NOT and fires"),
]


def definition(title, query, priority, group_by, note):
    return {
        "title": title,
        "description": f"Baseline: {note}",
        "remediation_steps": "",
        "priority": priority,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": query,
            "query_parameters": [],
            "filters": [],
            "streams": STREAMS,
            "stream_categories": [],
            "group_by": group_by,
            "series": [{"type": "count", "id": "count-0", "field": group_by[0]}],
            "conditions": {"expression": {
                "expr": ">",
                "left": {"expr": "number-ref", "ref": "count-0"},
                "right": {"expr": "number",
                          "value": THRESHOLD_PER_ALERT.get(title, 0.0)}}},
            "search_within_ms": WINDOW_MS,
            "execute_every_ms": EVERY_MS,
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        },
        "field_spec": {
            g: {"data_type": "string",
                "providers": [{"type": "template-v1",
                               "template": "${source." + g + "}",
                               "require_values": g == group_by[0]}]}
            for g in group_by
        },
        "key_spec": group_by,
        "notification_settings": {
            "grace_period_ms": GRACE_PER_ALERT.get(title, GRACE_MS),
            "backlog_size": 5},
        "notifications": [{"notification_id": MAIL, "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1",
                     "streams": ["000000000000000000000002"]}],
        "state": "ENABLED",
    }


# --------------------------------------------------------------------------
# Feed liveness. This is the one gap no window size can close: message
# timestamp is the O365 CreationTime, so after an outage the catch-up records
# arrive stamped hours in the past, land outside every window that will ever be
# evaluated, and silently alert on nothing. So detect the OUTAGE instead and
# treat it as "go inspect the catch-up range by hand".
#
# Window sized from 180 measured hours (6-13 Oct) on both feeds: zero empty
# hours, floor 10 records/hour, median 370 (GELF) and 554 (plaintext). Two
# hours rather than one because a SLIDING window can straddle the quiet tails
# of two adjacent hours even when no clock-hour was empty; and rather than the
# four hours suggested elsewhere, which would mean up to 4 hours blind.
LIVENESS_WINDOW_MS = 7_200_000    # 2 h
LIVENESS_GRACE_MS = 21_600_000    # 6 h - one mail per outage, not per run


def liveness_definition(title, stream_id, note):
    """count() < 1 with no grouping: fires when a feed stops arriving."""
    return {
        "title": title,
        "description": f"Baseline: {note}",
        "remediation_steps": "",
        "priority": 3,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": "",
            "query_parameters": [],
            "filters": [],
            "streams": [stream_id],
            "stream_categories": [],
            "group_by": [],
            "series": [{"type": "count", "id": "count-0"}],
            "conditions": {"expression": {
                "expr": "<",
                "left": {"expr": "number-ref", "ref": "count-0"},
                "right": {"expr": "number", "value": 1.0}}},
            "search_within_ms": LIVENESS_WINDOW_MS,
            "execute_every_ms": EVERY_MS,
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        },
        "field_spec": {},
        "key_spec": [],
        "notification_settings": {"grace_period_ms": LIVENESS_GRACE_MS,
                                  "backlog_size": 0},
        "notifications": [{"notification_id": MAIL, "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1",
                     "streams": ["000000000000000000000002"]}],
        "state": "ENABLED",
    }


def spray_definition():
    """One IP, many accounts. Needs a cardinality series, so it cannot use the
    normal builder. Historically the maximum distinct accounts failing a bad
    password from a single IP in 30 minutes is 1, so >3 has never fired."""
    return {
        "title": "O365 - password spray from one source",
        "description": ("Baseline: one ClientIP failing bad passwords against "
                        ">3 distinct accounts in 30 min. Max observed in 90d "
                        "is 1 account per IP, so this has never fired"),
        "remediation_steps": "",
        "priority": 3,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": ("Operation:UserLoginFailed "
                      "AND LogonError:InvalidUserNameOrPassword"),
            "query_parameters": [],
            "filters": [],
            "streams": STREAMS,
            "stream_categories": [],
            "group_by": ["ClientIP"],
            "series": [{"type": "card", "id": "card-0", "field": "UserId"}],
            "conditions": {"expression": {
                "expr": ">",
                "left": {"expr": "number-ref", "ref": "card-0"},
                "right": {"expr": "number", "value": 3.0}}},
            "search_within_ms": WINDOW_MS,
            "execute_every_ms": EVERY_MS,
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        },
        "field_spec": {"ClientIP": {"data_type": "string", "providers": [
            {"type": "template-v1", "template": "${source.ClientIP}",
             "require_values": True}]}},
        "key_spec": ["ClientIP"],
        "notification_settings": {"grace_period_ms": GRACE_MS, "backlog_size": 5},
        "notifications": [{"notification_id": MAIL, "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1",
                     "streams": ["000000000000000000000002"]}],
        "state": "ENABLED",
    }


# One per feed. If you run a single collector, delete the second entry.
LIVENESS = [
    ("O365 - GELF collector stopped sending",
     STREAMS[1],
     "No o365-logs records for 2h (floor was 10/hour over 180 measured hours). "
     "ACTION: check the GELF collector on dxc-vpn. IMPORTANT - once it resumes, "
     "the catch-up records carry their original CreationTime, so they land "
     "outside every alert window and will NOT retrigger any alert. Review the "
     "outage period by hand. While this feed is down the admin-consent, MFA and "
     "Microsoft-security-alert rules are blind, as they only work on GELF"),
    ("O365 - plaintext collector stopped sending",
     STREAMS[0],
     "No plaintext records for 2h (floor was 10/hour over 180 measured hours). "
     "ACTION: check the plaintext collector. Catch-up records keep their "
     "original CreationTime and will NOT retrigger alerts, so review the gap "
     "by hand. Retire this definition when the plaintext feed is retired"),
]


def all_definitions():
    return ([definition(*a) for a in ALERTS]
            + [spray_definition()]
            + [liveness_definition(*l) for l in LIVENESS])
