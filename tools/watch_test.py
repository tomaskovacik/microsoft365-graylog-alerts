#!/usr/bin/env python3
"""Watch the alert harness during a tenant emulation test.

For each alert it shows two independent numbers since --since minutes ago:
  RECORDS = raw audit records matching the alert's query (did the event reach
            Graylog at all?)
  EVENTS  = alert events Graylog actually generated (did the alert fire?)

RECORDS 0 / EVENTS 0  -> the tenant action has not arrived yet (MS publish lag)
RECORDS n / EVENTS 0  -> arrived but the alert did not fire: window, schedule
                         or grace period, NOT the query
RECORDS n / EVENTS n  -> working end to end

Usage: watch_test.py [since_minutes] [--loop]
"""
import collections, sys, time
import alerts, pg
from sync_alerts import req

S = STREAMS[0]


def snapshot(since_min):
    rng = int(since_min * 60)
    body = {"query": "", "page": 1, "per_page": 500, "filter": {},
            "timerange": {"type": "relative", "range": rng}}
    res, err = req("/api/events/search", body, "POST")
    evs = collections.Counter()
    if not err:
        for e in (res or {}).get("events", []):
            t = (e.get("event", {}) or {}).get("event_definition_id")
            evs[t] += 1
    defs, derr = req("/api/events/definitions?per_page=300")
    byid = {}
    if not derr:
        for d in defs.get("event_definitions", defs.get("elements", [])):
            byid[d["title"]] = d["id"]

    rows = []
    for title, query, prio, gb, note in alerts.ALERTS:
        n = pg.total(query, rng, S)
        did = byid.get(title)
        rows.append((title[7:], prio, n, evs.get(did, 0)))
    return rows


def show(since_min):
    rows = snapshot(since_min)
    print(f"\n  last {since_min} min            {'prio':>5}{'RECORDS':>9}{'EVENTS':>8}  verdict")
    for name, prio, rec, ev in rows:
        if rec == 0 and ev == 0:
            v = "-"
        elif rec and ev:
            v = "END TO END OK"
        elif rec and not ev:
            v = "arrived, ALERT DID NOT FIRE"
        else:
            v = "event without matching record (grace/overlap)"
        print(f"  {name:<34}{prio:>5}{str(rec):>9}{ev:>8}  {v}")


if __name__ == "__main__":
    since = float(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else 60
    show(since)
    if "--loop" in sys.argv:
        while True:
            time.sleep(120)
            show(since)
