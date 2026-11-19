"""Vendor API fakes (ofapi) for collectors whose security platform is not available.

ofapi runs locally from its checkout, over TLS because some collectors hardcode ``https://``.
Its control API scripts the vendor answers per test (``/_control/rules``) and records what the
collector sent (``/_control/journal``).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import httpx

from staticfire import runner
from staticfire.config import STATE_DIR
from staticfire.openaev import wait_until

OFAPI_RUN = "fake-ofapi"
OFAPI_PORT = int(os.environ.get("STATICFIRE_OFAPI_PORT", "8443"))
TLS_DIR = STATE_DIR / "tls"


def tls_files() -> tuple[Path, Path]:
    """A self-signed certificate for 127.0.0.1/localhost, created once."""
    cert, key = TLS_DIR / "cert.pem", TLS_DIR / "key.pem"
    if not cert.exists() or not key.exists():
        TLS_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "825",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )  # fmt: skip
    return cert, key


def ofapi_checkout(path: str | None = None) -> str:
    from staticfire.recipes import STATICFIRE_ROOT

    candidates = [Path(path).expanduser()] if path else []
    if env := os.environ.get("STATICFIRE_OFAPI_DIR"):
        candidates.append(Path(env))
    candidates += [STATICFIRE_ROOT.parent / "ofapi", Path.home() / "GitHub" / "ofapi"]
    for candidate in candidates:
        if (candidate / "app" / "main.py").exists():
            return str(candidate)
    raise FileNotFoundError(f"No ofapi checkout found (tried {[str(c) for c in candidates]})")


class Ofapi:
    def __init__(self, port: int = OFAPI_PORT):
        cert, _ = tls_files()
        self.cert = cert
        self.base = f"https://127.0.0.1:{port}"
        self.http = httpx.Client(base_url=self.base, verify=str(cert), timeout=10)
        # Whether ofapi_up started this instance (a recipe then stops it) or reused one
        self.started = False

    def url(self, path: str) -> str:
        """What a collector needs as its vendor host, e.g. ``127.0.0.1:8443/<vendor>``."""
        return f"{self.base.removeprefix('https://')}/{path.strip('/')}"

    def alive(self) -> bool:
        try:
            return self.http.get("/_control/rules").status_code == 200
        except httpx.HTTPError:
            return False

    def reset(self) -> None:
        self.http.post("/_control/reset").raise_for_status()

    def rule(self, path: str, responses: list[dict], then: str = "last", method=None) -> dict:
        body = {"path": path, "responses": responses, "then": then}
        if method:
            body["method"] = method
        return self.http.post("/_control/rules", json=body).raise_for_status().json()

    def journal(self, path: str = "") -> list[dict]:
        response = self.http.get("/_control/journal", params={"path": path} if path else None)
        data = response.raise_for_status().json()
        return data.get("entries", data) if isinstance(data, dict) else data


def ofapi_up(path: str | None = None, port: int = OFAPI_PORT, timeout: float = 60) -> Ofapi:
    """Reuse a running ofapi on the port, or start one from its checkout."""
    fake = Ofapi(port)
    if fake.alive():
        return fake
    checkout = ofapi_checkout(path)
    cert, key = tls_files()
    runner.stop(OFAPI_RUN)
    runner.spawn(
        OFAPI_RUN,
        [
            "uv", "run", "--directory", checkout,
            "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port),
            "--ssl-keyfile", str(key), "--ssl-certfile", str(cert),
        ],
        cwd=checkout,
        env={},
        kind="fake",
        name="ofapi",
    )  # fmt: skip
    started, _ = wait_until(fake.alive, timeout, 1)
    if not started:
        raise RuntimeError(f"ofapi did not start: {runner.tail(OFAPI_RUN, 30)}")
    fake.started = True
    return fake
