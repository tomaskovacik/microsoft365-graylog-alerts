#!/usr/bin/env python3
"""Read-only helper for the production Graylog."""
import base64
import json
import os
import urllib.parse
import urllib.request

from config import BASE
HERE = os.path.dirname(os.path.abspath(__file__))
TOK = open(os.path.join(HERE, ".gltok")).read().strip()
AUTH = base64.b64encode(f"{TOK}:token".encode()).decode()


def call(path):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", f"Basic {AUTH}")
    req.add_header("X-Requested-By", "cli")
    req.add_header("Accept", "application/json")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=90).read().decode())
    except urllib.error.HTTPError as e:
        return {"__error__": e.code, "body": e.read().decode()[:300]}


def search(query, range_s=86400, limit=150, offset=0, stream=None):
    p = (f"/api/search/universal/relative?query={urllib.parse.quote(query)}"
         f"&range={range_s}&limit={limit}&offset={offset}")
    if stream:
        p += f"&filter={urllib.parse.quote('streams:' + stream)}"
    return call(p)


def pull(query, range_s=86400, cap=6000, stream=None):
    """Page through results, returning message dicts."""
    out = []
    for off in range(0, cap, 150):
        r = search(query, range_s, 150, off, stream)
        if "__error__" in r:
            return out, r
        batch = [m["message"] for m in r.get("messages", [])]
        if not batch:
            break
        out += batch
    return out, None


def total(query, range_s=86400, stream=None):
    r = search(query, range_s, 1, 0, stream)
    return r.get("total_results") if "__error__" not in r else r
