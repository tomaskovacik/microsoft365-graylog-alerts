#!/usr/bin/env python3
"""Keep Graylog's `o365-delegates` lookup table current.

Writes OUT_FILE (default /out/o365_delegates.csv, i.e. lookuptablescsv/ on the
host, which Graylog re-reads every 5 minutes) as `"pair","source"` rows, where
pair = "<reader>><mailbox>" lower-cased. The O365 pipeline rule "o365 delegate
mailbox access" looks every delegate mailbox read up in it, and the alert
"O365 - new delegate reading a mailbox" fires on pairs that are missing.

Sources, merged every INTERVAL_SECONDS:
  observed  - every pair that actually read a mailbox as a delegate
              (MailItemsAccessed, LogonType 2) in the last LOOKBACK_DAYS,
              from Graylog itself. So a new pair alerts ONCE, on first use,
              and is learned on the next run; a pair unused for LOOKBACK_DAYS
              drops out and alerts again if it comes back.
  <file>    - every other *.csv in the output directory whose name starts with
              "o365_delegates_" (e.g. o365_delegates_export.csv written by the
              microsoft365-graylog-alerts PowerShell helper, or a hand-kept
              o365_delegates_manual.csv). Pre-approves pairs before first use.

Never writes an empty file (every delegate read would alert), and if Graylog
cannot be queried keeps the previously learned pairs rather than dropping them.
Standard library only, so it runs on a stock python image.
"""
import csv, glob, json, os, sys, time, urllib.request, urllib.error
from base64 import b64encode
from datetime import datetime, timezone

GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://graylog:9000").rstrip("/")
TOKEN = os.environ.get("GRAYLOG_TOKEN", "")
STREAM_ID = os.environ.get("O365_STREAM_ID", "")
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "90"))
INTERVAL = int(os.environ.get("INTERVAL_SECONDS", "3600"))
OUT_FILE = os.environ.get("OUT_FILE", "/out/o365_delegates.csv")
QUERY = "Operation:MailItemsAccessed AND LogonType:2"


def log(msg):
    print(f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} {msg}", flush=True)


def norm(addr):
    return (addr or "").strip().strip('"').lower()


def observed_pairs():
    """One Graylog aggregation: distinct (UserId, MailboxOwnerUPN)."""
    body = {"queries": [{
        "id": "q",
        "query": {"type": "elasticsearch", "query_string": QUERY},
        "timerange": {"type": "relative", "range": LOOKBACK_DAYS * 86400},
        "filter": {"type": "or", "filters": [{"type": "stream", "id": STREAM_ID}]},
        "search_types": [{
            "id": "p", "type": "pivot", "rollup": False, "sort": [],
            "row_groups": [{"type": "values", "limit": 10000,
                            "fields": ["UserId", "MailboxOwnerUPN"]}],
            "column_groups": [],
            "series": [{"type": "count", "id": "c"}]}]}]}
    req = urllib.request.Request(GRAYLOG_URL + "/api/views/search/sync",
                                 data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization",
                   "Basic " + b64encode(f"{TOKEN}:token".encode()).decode())
    req.add_header("X-Requested-By", "o365-delegates-sync")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        res = json.loads(r.read())["results"]["q"]
    if res.get("errors"):
        raise RuntimeError(f"search errors: {res['errors']}")
    pairs = set()
    for row in res["search_types"]["p"]["rows"]:
        if len(row.get("key", [])) == 2:
            user, mailbox = map(norm, row["key"])
            if "@" in user and "@" in mailbox and user != mailbox:
                pairs.add(f"{user}>{mailbox}")
    return pairs


def file_pairs(path):
    """Accepts our own pair,source format, or any CSV with mailbox + user columns."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = csv.DictReader(f)
        cols = {c.lower().replace(" ", ""): c for c in rows.fieldnames or []}
        pcol = cols.get("pair")
        mcol = next((cols[c] for c in ("mailbox", "group", "identity",
                                       "primarysmtpaddress") if c in cols), None)
        ucol = next((cols[c] for c in ("user", "member", "userprincipalname",
                                       "trustee") if c in cols), None)
        for r in rows:
            if pcol:
                pair = norm(r[pcol])
            elif mcol and ucol:
                pair = f"{norm(r[ucol])}>{norm(r[mcol])}"
            else:
                raise ValueError(f"no pair or mailbox+user columns: {rows.fieldnames}")
            user, _, mailbox = pair.partition(">")
            if "@" in user and "@" in mailbox and user != mailbox:
                yield pair


def previous():
    try:
        with open(OUT_FILE, newline="") as f:
            return {r["pair"]: set(r["source"].split("+")) for r in csv.DictReader(f)}
    except (OSError, KeyError):
        return {}


def run_once():
    prev = previous()
    sources = {}

    try:
        obs = observed_pairs()
        log(f"graylog: {len(obs)} delegate pairs in the last {LOOKBACK_DAYS} days")
    except (urllib.error.URLError, RuntimeError, KeyError, ValueError) as e:
        obs = {p for p, s in prev.items() if "observed" in s}
        log(f"ERROR graylog query failed ({e}); keeping {len(obs)} previously learned pairs")
    for p in obs:
        sources.setdefault(p, set()).add("observed")

    out_dir, out_name = os.path.split(OUT_FILE)
    for path in sorted(glob.glob(os.path.join(out_dir, "o365_delegates_*.csv"))):
        if os.path.basename(path) == out_name:
            continue
        tag = os.path.basename(path)[len("o365_delegates_"):-len(".csv")]
        try:
            n = 0
            for p in file_pairs(path):
                sources.setdefault(p, set()).add(tag)
                n += 1
            log(f"{os.path.basename(path)}: {n} pairs")
        except (OSError, ValueError, csv.Error) as e:
            log(f"ERROR {os.path.basename(path)} skipped: {e}")

    if not sources:
        log("ERROR no pairs from any source - leaving the existing file untouched")
        return

    new = sorted(sources)
    added = [p for p in new if p not in prev]
    dropped = [p for p in prev if p not in sources]
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["pair", "source"])
        for p in new:
            w.writerow([p, "+".join(sorted(sources[p]))])
    os.replace(tmp, OUT_FILE)   # atomic: Graylog never reads a half-written file
    log(f"wrote {len(new)} pairs to {OUT_FILE} (+{len(added)} -{len(dropped)})")
    for p in added:
        log(f"  added   {p} ({'+'.join(sorted(sources[p]))})")
    for p in dropped:
        log(f"  dropped {p}")


if __name__ == "__main__":
    if not TOKEN or not STREAM_ID:
        # Sleep rather than exit, so a stack deployed before the token is
        # configured does not crash-loop.
        log("ERROR GRAYLOG_TOKEN and O365_STREAM_ID must be set; idle")
        while True:
            time.sleep(3600)
    once = "--once" in sys.argv
    while True:
        try:
            run_once()
        except Exception as e:   # keep the loop alive whatever happens
            log(f"ERROR unexpected: {e!r}")
        if once:
            break
        time.sleep(INTERVAL)
