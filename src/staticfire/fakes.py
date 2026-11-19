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
OFAPI_HTTP_PORT = int(os.environ.get("STATICFIRE_OFAPI_HTTP_PORT", "8000"))
LAUNCHER = Path(__file__).with_name("ofapi_dual.py")
PROXY_RUN = "fake-proxy"
PROXY_PORT = int(os.environ.get("STATICFIRE_PROXY_PORT", "8899"))
PROXY_ADDON = Path(__file__).with_name("proxy_addon.py")
PROXY_DIR = STATE_DIR / "mitmproxy"
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
    """The same fake on https://127.0.0.1:<port> and http://127.0.0.1:<http_port>."""

    def __init__(self, port: int = OFAPI_PORT, http_port: int = OFAPI_HTTP_PORT):
        cert, _ = tls_files()
        self.cert = cert
        self.base = f"https://127.0.0.1:{port}"
        self.http_base = f"http://127.0.0.1:{http_port}"
        self.http = httpx.Client(base_url=self.base, verify=str(cert), timeout=10)
        # Whether ofapi_up started this instance (a recipe then stops it) or reused one
        self.started = False

    def url(self, path: str) -> str:
        """What a collector needs as its vendor host, e.g. ``127.0.0.1:8443/<vendor>``."""
        return f"{self.base.removeprefix('https://')}/{path.strip('/')}"

    def http_url(self, path: str = "") -> str:
        return f"{self.http_base}/{path.strip('/')}".rstrip("/")

    def https_url(self, path: str = "") -> str:
        return f"{self.base}/{path.strip('/')}".rstrip("/")

    def alive(self) -> bool:
        try:
            return self.http.get("/_control/rules").status_code == 200
        except httpx.HTTPError:
            return False

    def reset(self, prefix: str = "") -> None:
        """Forget rules and journal (only those under ``prefix`` when given: tests can share)."""
        params = {"prefix": prefix} if prefix else None
        self.http.post("/_control/reset", params=params).raise_for_status()

    def reload(self) -> list[str]:
        """Load the vendor modules added or changed since ofapi started."""
        return self.http.post("/_control/reload").raise_for_status().json()["reloaded"]

    def hosts(self) -> dict[str, str]:
        return self.http.get("/_control/hosts").raise_for_status().json()

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
    """Reuse a running ofapi on the port, or start one from its checkout (HTTP and TLS)."""
    fake = Ofapi(port)
    if fake.alive():
        return fake
    checkout = ofapi_checkout(path)
    cert, key = tls_files()
    runner.stop(OFAPI_RUN)
    runner.spawn(
        OFAPI_RUN,
        [
            "uv", "run", "--directory", checkout, "python", str(LAUNCHER),
            str(OFAPI_HTTP_PORT), str(port), str(cert), str(key),
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


class Proxy:
    """The TLS-intercepting proxy in front of ofapi (see proxy_addon.py)."""

    def __init__(self, port: int = PROXY_PORT):
        self.url = f"http://127.0.0.1:{port}"
        self.ca = PROXY_DIR / "mitmproxy-ca-cert.pem"
        self.bundle = TLS_DIR / "proxy-bundle.pem"

    def alive(self) -> bool:
        try:
            with httpx.Client(proxy=self.url, timeout=5) as client:
                return client.get("http://ofapi.staticfire/_control/rules").status_code == 200
        except httpx.HTTPError:
            return False

    def write_bundle(self) -> Path:
        """Public CAs, the proxy's CA and ofapi's own certificate, for the code under test."""
        import certifi

        cert, _ = tls_files()
        parts = [Path(certifi.where()).read_text(), self.ca.read_text(), cert.read_text()]
        content = "\n".join(parts)
        if not self.bundle.exists() or self.bundle.read_text() != content:
            # atomically: running connectors read it on every new TLS connection
            temporary = self.bundle.with_suffix(f".{os.getpid()}.tmp")
            temporary.write_text(content)
            os.replace(temporary, self.bundle)
        return self.bundle

    def trust_env(self) -> dict[str, str]:
        """What makes the usual HTTP clients trust the proxy's and ofapi's certificates."""
        bundle = str(self.bundle)
        names = (
            "REQUESTS_CA_BUNDLE",  # requests
            "SSL_CERT_FILE",  # ssl's default context: urllib, httpx, aiohttp
            "CURL_CA_BUNDLE",
            "AWS_CA_BUNDLE",  # botocore
            "HTTPLIB2_CA_CERTS",  # google-api-python-client
            "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
            "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO",
        )
        return dict.fromkeys(names, bundle)

    def env(self, no_proxy: list[str]) -> dict[str, str]:
        """What makes a process send its HTTP(S) through the proxy and trust it."""
        bypass = ",".join(["127.0.0.1", "localhost", *no_proxy])
        return {
            "HTTP_PROXY": self.url,
            "HTTPS_PROXY": self.url,
            "http_proxy": self.url,
            "https_proxy": self.url,
            "NO_PROXY": bypass,
            "no_proxy": bypass,
            **self.trust_env(),
        }


def proxy_up(fake: Ofapi, port: int = PROXY_PORT, timeout: float = 60) -> Proxy:
    """Reuse a running proxy on the port, or start one (mitmdump through uvx)."""
    proxy = Proxy(port)
    if proxy.alive():
        proxy.write_bundle()
        return proxy
    PROXY_DIR.mkdir(parents=True, exist_ok=True)
    runner.stop(PROXY_RUN)
    runner.spawn(
        PROXY_RUN,
        [
            "uvx", "--from", "mitmproxy", "mitmdump",
            "--listen-host", "127.0.0.1", "--listen-port", str(port),
            "--set", f"confdir={PROXY_DIR}",
            # Never contact the real host: the request goes to ofapi
            "--set", "connection_strategy=lazy",
            "--set", "upstream_cert=false",
            "--set", "flow_detail=0",
            "-s", str(PROXY_ADDON),
        ],
        cwd=str(PROXY_DIR),
        env={"STATICFIRE_OFAPI_HTTP": fake.http_base},
        kind="fake",
        name="proxy",
    )  # fmt: skip
    started, _ = wait_until(proxy.alive, timeout, 1)
    if not started:
        raise RuntimeError(f"the proxy did not start: {runner.tail(PROXY_RUN, 30)}")
    proxy.write_bundle()
    return proxy
