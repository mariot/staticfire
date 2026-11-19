"""mitmproxy addon sending every proxied request to ofapi, where the fake of its host answers.

A connector run with HTTP(S)_PROXY pointing at this proxy (and trusting its CA) reaches the fakes
even when its vendor URL is hardcoded. ofapi's vendor modules declare their real hosts
(``/_control/hosts``); a request to ``https://api.vendor.com/v2/x`` becomes
``http://127.0.0.1:8000/<vendor prefix>/v2/x``. Hosts no fake claims go to
``/_unrouted/<host>/...``, which ofapi journals and answers 404: nothing leaves the machine, and
the journal tells which fake is missing.

Run: mitmdump -s proxy_addon.py (STATICFIRE_OFAPI_HTTP=http://127.0.0.1:8000)
"""

import fnmatch
import json
import os
import time
import urllib.request
from urllib.parse import urlparse

from mitmproxy import http

OFAPI = urlparse(os.environ.get("STATICFIRE_OFAPI_HTTP", "http://127.0.0.1:8000"))
# Requests to this host reach ofapi itself (health checks, control API)
SELF_HOST = "ofapi.staticfire"
REFRESH_SECONDS = 2.0

_hosts: dict[str, str] = {}
_fetched = 0.0


def _routes() -> dict[str, str]:
    global _hosts, _fetched
    if time.monotonic() - _fetched > REFRESH_SECONDS:
        try:
            with urllib.request.urlopen(f"{OFAPI.geturl()}/_control/hosts", timeout=2) as reply:
                _hosts = json.load(reply)
            _fetched = time.monotonic()
        except Exception:  # keep the last known map while ofapi reloads
            pass
    return _hosts


def prefix_for(host: str, routes: dict[str, str]) -> str:
    if host == SELF_HOST:
        return ""
    # Exact hosts win over patterns, longer patterns over shorter ones
    for pattern in sorted(routes, key=lambda p: ("*" in p, -len(p))):
        if fnmatch.fnmatch(host, pattern):
            return routes[pattern].rstrip("/")
    return f"/_unrouted/{host}"


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    prefix = prefix_for(host, _routes())
    flow.request.headers["X-Original-Host"] = host
    flow.request.headers["X-Original-Scheme"] = flow.request.scheme
    flow.request.scheme = "http"
    flow.request.host = OFAPI.hostname
    flow.request.port = OFAPI.port or 80
    flow.request.path = prefix + flow.request.path
