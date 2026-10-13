# Microsoft 365 audit alerts for Graylog

29 security alerts for Microsoft 365 / Entra audit logs, as an importable
Graylog content pack plus a small harness for tuning them.

(The source API is still named the *Office 365 Management Activity API*, so that
name appears throughout where it refers to the API itself.)

Companion to
[office365-audit-log-collector](https://github.com/tomaskovacik/office365-audit-log-collector),
which gets the logs in. This gets you alerted on them.

Every query and every threshold here was validated against 90 days of real
tenant data before it was included. That matters more than it sounds, and the
rest of this README explains why.

## Install

1. **System → Content Packs → Upload**, select `content-pack.json`, install.
2. Set the notification recipients — the pack ships with none, deliberately.
3. Point the definitions at your own stream.
4. Edit the per-user country exceptions in the two geo alerts. They ship with
   `example.com` placeholders so that an unedited import cannot silently
   inherit someone else's assumptions.

Then, before trusting any of it, read the next section.

## The failure modes this set exists to avoid

These cost real debugging time. None of them are documented by Microsoft or
Graylog, and most fail *silently* — the alert does not error, it simply never
fires.

### 1. An aggregation window shorter than your ingest lag never fires

The collector sets each message's `timestamp` to the Office 365 `CreationTime`,
so Graylog's aggregation window is measured in **event time**, not arrival
time. Records arrive late: a median of 5.3 minutes in one production tenant,
p95 9.4, maximum 14.

A 5-minute window evaluated every 5 minutes therefore gives a record about 2.5
minutes to arrive. Most events land in a window that has already been evaluated
and are never seen again. The alerts look healthy and report "never fired".

These definitions use a **30-minute window evaluated every 5 minutes**, so each
event is covered by six overlapping runs, with the grace period raised to match
so the overlap still sends one mail. Measure your own lag before changing it:

```
timestamp field  = event time (CreationTime)
gl2_receive_timestamp = arrival time
```

The side effect is up to six duplicate events per real event in the All events
stream. The grace period keeps it to one email.

### 2. No window size survives a collector outage — alert on the outage

After an outage the catch-up records arrive stamped hours in the past, land
outside every window that will ever be evaluated, and fire nothing. The data is
in Graylog, fully searchable, and silently un-alerted.

Widening cannot fix this: covering a 12-hour outage means re-evaluating 12
hours of history every 5 minutes. So detect the *outage* instead. The two
`collector stopped sending` definitions do this with `count() < 1` and no
grouping.

Graylog **does** emit an event on a zero-row aggregation — verified by
backfilling a window where the stream was genuinely empty. Do not take that on
trust in your own version; test it.

Window sized from 180 measured hours: zero empty hours, floor 10 records/hour.
Two hours rather than one, because a sliding window can straddle the quiet
tails of two adjacent hours even when no clock-hour was empty.

### 3. One inconsistent field type silently drops whole documents

OpenSearch infers a field's type from the first value it sees in an index, then
rejects the **entire document** when a later value will not parse as that type.
You lose the whole audit record, not the field.

Office 365 sends at least two fields with inconsistent types:

| field | seen as |
|---|---|
| `ListBaseType` | `1` on `FileAccessed`, `"DocumentLibrary"` on `ListViewed` |
| `RequestType` | numeric on some sign-ins, `"OAuth2:Authorize"` elsewhere |

In one tenant a single 7-day backfill lost 602 documents to `RequestType`
alone. The only evidence is **System → Overview → Indexer failures**.

Fix on either side: pin the field with **System → Indices → _index set_ → Field
Types → Change field type → string** (applies to new indices, so rotate
afterwards), or coerce at the collector with its `stringFields` option.

### 4. Operation names differ from the documentation, per tenant

`Add OAuth2PermissionGrant.` appears throughout Microsoft's documentation. One
tenant emitted it **zero** times in 90 days; the real application-permission
grant was `Add app role assignment to service principal.`

There are two naming formats and they are not equally trustworthy:

- **Exchange cmdlets** (`New-TransportRule`, `Set-MailboxAuditBypassAssociation`)
  are logged under the literal cmdlet name. Verified across 23 distinct values
  plus live tests. Safe to write from the documentation.
- **Entra friendly strings** (`Add member to role.`, `Set domain
  authentication.`) vary. This is the format that produced the dead query
  above. Confirm against your own data.

`sync.py --dry` prints how many records each query would have matched over the
last 90 days. A new query returning 0 where you expected activity is the signal.

### 5. `Operation` is case-sensitive, and not everything is canonicalised

It is a keyword field, so matching is exact. Exchange canonicalises
admin-invoked cmdlets — typing `sEt-mailboxAuditBypassAssociation` logs as
`Set-MailboxAuditBypassAssociation`, verified — so case-sensitive queries are
safe for admin actions.

Microsoft's own internal operations are **not** canonicalised. One tenant has
`enable-AddressListPaging` 43 times and the canonical spelling zero times. Take
internal operation names from your data, never from documentation.

### 6. `Operation:UserLoggedIn` in geo rules is load-bearing

`ClientIP` is whoever called the API, which is frequently Microsoft. In one
tenant ~2,600 records per 90 days geolocate to Azure regions — Zurich, Dublin,
Stockholm, Warsaw — on `FileAccessed`, `FilePreviewed` and `Update`
operations, under `UserType: 0`, which looks exactly like ordinary user
activity.

Restricting to `UserLoggedIn` removes all of it. Broaden these rules past
`UserLoggedIn` and they will fire on Microsoft's datacenters forever.

Geo rules also need `_exists_:ClientIP_country_code`. Without it, any record
missing the geoip field satisfies the `NOT` and fires.

### 7. Group by `ObjectId`, not `UserId`, when the actor is a service

Several high-value events are performed by Microsoft service principals on a
user's behalf. Grouping by `UserId` produces alerts naming
`ServicePrincipal_9487dbed-…` or the literal string `SecurityComplianceAlerts`,
never the person.

| alert | actor (`UserId`) | subject (`ObjectId`) |
|---|---|---|
| MFA method changed | Azure MFA service principal | the user whose MFA changed |
| Microsoft security alert | `SecurityComplianceAlerts` | the affected user |

### 8. `ModifiedProperties` and `Parameters` are unsearchable as raw JSON

Both arrive as multi-kilobyte blobs in a keyword field. Exact match fails
because the whole value must match; substring needs a leading wildcard, which
OpenSearch disables by default.

If your collector flattens them into real fields — as the companion collector's
GELF output does — several alerts become possible that otherwise are not:

- **admin consent**, via `ConsentContext_IsAdminConsent_NewValue`, which
  separates 9 admin consents from 118 ordinary user consents
- **MFA changes**, via `StrongAuthenticationPhoneAppDetail_*`
- **mail forwarding**, via `ForwardTo` / `ForwardingSmtpAddress`

Those four definitions only work on a flattened feed. They are marked as such.

### 9. Measure thresholds, do not guess them

`UserLoginFailed` alone is useless: MFA interrupts are logged as failures, and
legitimate users reached **64 failures in a 30-minute window**. Restricted to
`LogonError:InvalidUserNameOrPassword` the worst real user managed 15 and p95
was 5, which is what makes a threshold of 10 meaningful.

Password spray is measured the other way — distinct accounts failing from one
source IP, where the observed maximum was 1.

## What Microsoft already covers

Before building a detection, check whether Purview already has it. Microsoft's
**default** alert policies — no Defender P2 required — emit into the audit feed
as `RecordType: 40`, so the `Microsoft security alert raised` definition relays
anything they detect into Graylog automatically, including policies you gain
later by upgrading.

One tenant's `Creation of forwarding/redirect rule` policy fired 12 times in 90
days, correctly, on rules carrying `ForwardTo` — and ignored pure
`MoveToFolder` rules. It cannot distinguish internal from external recipients,
which is its main limitation.

`mail forwarding configured` here is complementary rather than duplicative: it
covers `Set-Mailbox` forwarding, which needs no inbox rule and so never
triggers Microsoft's policy.

## Tools

Not required to run the alerts — Graylog stores them itself. These are for
building and tuning.

```bash
cp tools/config.example.py tools/config.py   # streams, notification, exceptions
echo -n 'your-graylog-token' > tools/.gltok  # chmod 600

python3 tools/sync.py --dry      # validate + 90-day hit count per alert
python3 tools/sync.py --apply    # create or update, by title, idempotent
python3 tools/watch_test.py 60   # RECORDS vs EVENTS while testing
```

`sync.py --dry` is the habit worth keeping: it tells you what a query change
would have matched over the last 90 days *before* you apply it. That is how you
catch a query that matches nothing.

`watch_test.py` answers the first question when something does not alert, by
separating the two possible causes:

```
RECORDS 0 / EVENTS 0  -> the record has not arrived yet (publishing lag)
RECORDS n / EVENTS 0  -> it arrived but the alert did not fire: window,
                         schedule or grace - not the query
RECORDS n / EVENTS n  -> working end to end
```

## Testing an alert without waiting for an incident

Graylog can replay a definition over a historical window, which fires it for
real — events, notifications and all:

```bash
curl -u "$TOKEN:token" -H 'Content-Type: application/json' \
  -X POST "$GRAYLOG/api/events/definitions/$ID/execute" \
  -d '{"type":"aggregation-v1","timerange":{"type":"absolute",
       "from":"2026-10-12T06:45:00.000Z","to":"2026-10-12T07:00:00.000Z"}}'
```

Pick a window containing exactly one known matching record and you get one
event and one email. This is how every alert in this pack was verified, along
with deliberately performing the action in a test tenant where no historical
record existed.

## Licence

MIT, matching the companion collector.
