"""Copy to config.py and edit. Nothing here is portable between tenants.

Find the stream and notification IDs in their Graylog URLs, e.g.
  /streams/0000000000000000000000aa/...
  /alerts/notifications  -> edit a notification, the id is in the URL
"""

BASE = "http://graylog.example.com:9000"

# Streams the alerts search. List every stream your Office 365 records land in.
# Four definitions only work on a feed where ModifiedProperties and Parameters
# are flattened into real fields (admin consent, MFA method changed, mail
# forwarding, Microsoft security alert); on a raw-JSON feed they match nothing.
STREAMS = [
    "0000000000000000000000aa",   # e.g. plaintext / raw JSON input
    "0000000000000000000000bb",   # e.g. GELF input
]

# Notification to attach to every definition.
MAIL = "0000000000000000000000cc"

# --- geo rules -------------------------------------------------------------

# Where your people normally are. Everything else alerts, except the per-user
# exceptions below.
HOME_CC = "SK"

# Allowlist for the broader "outside EU/EEA" rule: EU, plus the rest of the
# EEA (IS/LI/NO), CH and GB. Trim it for a stricter policy - but check what
# that costs first with `sync.py --dry`, because one user behind a VPN exit in
# an adjacent country can account for most of the hits.
ALLOWED_CC = ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
              "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
              "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO", "CH", "GB"]

# People who legitimately sign in from elsewhere. Resolve the network owner of
# each address before adding an entry: a user who looks "based in country X"
# may be on a rentable commercial VPN that exits there, in which case the geo
# rules cannot protect that account and you should know that explicitly.
#
# Holidays do NOT belong here - a trip is exactly what these rules should show.
USER_HOME_CC = {
    # "based.abroad@example.com": ["EE"],
    # "vpn.user1@example.com": ["BE"],
    # "vpn.user2@example.com": ["BE"],
    # "traveller@example.com": ["LI", "AT", "CH"],
}
