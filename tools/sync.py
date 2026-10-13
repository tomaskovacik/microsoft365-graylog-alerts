#!/usr/bin/env python3
"""Reconcile Graylog's event definitions with alerts.all_definitions().

  --dry     validate every query + definition, show create/update plan
  --apply   POST new definitions, PUT changed ones
"""
import base64, json, os, sys, urllib.error, urllib.request
import alerts, pg

from config import BASE
TOK = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gltok")).read().strip()
AUTH = base64.b64encode(f"{TOK}:token".encode()).decode()


def req(path, body=None, method="GET"):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Authorization", f"Basic {AUTH}")
    r.add_header("X-Requested-By", "cli")
    r.add_header("Accept", "application/json")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            raw = resp.read().decode()
            return (json.loads(raw) if raw.strip() else {}), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode()[:260]}"


def current():
    d, err = req("/api/events/definitions?per_page=300")
    if err:
        print("cannot list definitions:", err); sys.exit(1)
    evs = d.get("event_definitions", d.get("elements", []))
    return {e["title"]: e for e in evs}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "--dry"
    have = current()
    want = alerts.all_definitions()
    live_streams = {s["id"] for s in (req("/api/streams")[0] or {}).get("streams", [])}

    plan = []
    for d in want:
        d["config"]["streams"] = [s for s in d["config"]["streams"] if s in live_streams]
        ex = have.get(d["title"])
        plan.append(("update" if ex else "create", d, ex))

    if mode == "--dry":
        print(f"{'action':<8}{'alert':<44}{'hits/90d':>9}  query status")
        for act, d, ex in plan:
            q = d["config"]["query"]
            n = pg.total(q or '*', 90 * 86400, STREAMS[0])
            qs = "OK" if isinstance(n, int) else f"ERROR {n}"
            # Graylog-side schema validation
            vd = dict(d); vd["id"] = ex["id"] if ex else "0"*24
            v, err = req("/api/events/definitions/validate", vd, "POST")
            if err:
                vs = f"validate failed: {err}"
            else:
                fe = v.get("failed") or v.get("errors") or {}
                vs = "valid" if not fe else f"INVALID {fe}"
            print(f"{act:<8}{d['title']:<44}{str(n):>9}  {qs}; {vs}")
        sys.exit(0)

    for act, d, ex in plan:
        if act == "create":
            res, err = req("/api/events/definitions", {"entity": d}, "POST")
        else:
            body = dict(d); body["id"] = ex["id"]
            res, err = req(f"/api/events/definitions/{ex['id']}", body, "PUT")
            if err and "entity" in (err or ""):
                res, err = req(f"/api/events/definitions/{ex['id']}",
                               {"entity": body}, "PUT")
        if err:
            print(f"  FAILED  {act:<7}{d['title']}\n          {err}")
            sys.exit(1)
        print(f"  {act}d  {d['title']}")
    print(f"\n{len(plan)} definitions reconciled")
