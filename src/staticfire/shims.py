"""A ``sitecustomize`` making a connector's test environment look like its production one,
without touching its code.

* certifi answers the proxy's bundle (``SSL_CERT_FILE``): code passing ``verify=True`` to
  ``requests.Session.send`` validates against certifi whatever ``REQUESTS_CA_BUNDLE`` says, as
  the real vendor's certificate would pass.
* without libmagic on this machine (python-magic cannot load), a ``magic`` module using the
  file(1) command stands in for python-magic.
* the network stops at the machine: a host other than the platform's, this machine's or one in
  ``STATICFIRE_NETWORK_ALLOW`` does not resolve, and no connection goes to a public address. A
  client ignoring the proxy then fails loudly instead of reaching the real vendor.
* ``rabbitmq`` resolves to ``MQ_HOST``: OpenCTI advertises its RabbitMQ by its Docker name,
  which a connector deployed next to it resolves; one taking the advertised settings over its
  helper's (diode-import) would not reach it from this machine.
"""

from __future__ import annotations

from pathlib import Path

from staticfire.config import STATE_DIR

SITECUSTOMIZE = """\
import os
import socket

try:
    import certifi

    if os.environ.get("SSL_CERT_FILE"):
        certifi.where = lambda: os.environ["SSL_CERT_FILE"]
        certifi.contents = lambda: open(os.environ["SSL_CERT_FILE"]).read()
except ImportError:
    pass

import ipaddress
from urllib.parse import urlparse

_getaddrinfo = socket.getaddrinfo


def _allowed_hosts():
    hosts = {"localhost", "rabbitmq", os.environ.get("MQ_HOST", "")}
    for name in ("NO_PROXY", "no_proxy", "STATICFIRE_NETWORK_ALLOW"):
        hosts |= {h.strip().lower() for h in os.environ.get(name, "").split(",")}
    for name in ("OPENCTI_URL", "OPENAEV_URL"):
        hosts.add((urlparse(os.environ.get(name, "")).hostname or "").lower())
    return {h for h in hosts if h}


_ALLOWED = _allowed_hosts()


def _local(address):
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local or address in _ALLOWED


def _resolve(host, *args, **kwargs):
    if host == "rabbitmq" and os.environ.get("MQ_HOST"):
        host = os.environ["MQ_HOST"]
    name = host.decode() if isinstance(host, bytes) else str(host or "")
    if name and name.lower() not in _ALLOWED and not _local(name):
        raise socket.gaierror(
            socket.EAI_NONAME, f"staticfire: {name} is outside the test (use the proxy)"
        )
    return _getaddrinfo(host, *args, **kwargs)


def _guard(original):
    def guarded(self, address, *args):
        target = address[0] if isinstance(address, tuple) else None
        if isinstance(target, str) and not _local(target):
            raise ConnectionRefusedError(f"staticfire: {target} is outside the test")
        return original(self, address, *args)

    return guarded


def _guard_sendto(original):
    def guarded(self, data, *args):
        address = args[-1] if args else None
        if isinstance(address, tuple) and not _local(str(address[0])):
            raise ConnectionRefusedError(f"staticfire: {address[0]} is outside the test")
        return original(self, data, *args)

    return guarded


socket.getaddrinfo = _resolve
socket.socket.connect = _guard(socket.socket.connect)
socket.socket.connect_ex = _guard(socket.socket.connect_ex)
socket.socket.sendto = _guard_sendto(socket.socket.sendto)
"""


MAGIC = """\
import subprocess


def from_buffer(buffer, mime=False):
    option = "--mime-type" if mime else "--brief"
    out = subprocess.run(["/usr/bin/file", option, "-b", "-"], input=buffer, capture_output=True)
    return out.stdout.decode().strip()


def from_file(path, mime=False):
    with open(path, "rb") as stream:
        return from_buffer(stream.read(), mime)
"""


def _has_libmagic() -> bool:
    import ctypes.util

    return ctypes.util.find_library("magic") is not None or any(
        Path(folder, "libmagic.dylib").exists()
        for folder in ("/opt/homebrew/lib", "/usr/local/lib")
    )


def env(existing: str | None = None) -> dict[str, str]:
    """``PYTHONPATH`` putting the shim first (before ``existing``)."""
    folder = STATE_DIR / "shims"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "sitecustomize.py").write_text(SITECUSTOMIZE)
    magic = folder / "magic.py"
    if _has_libmagic():
        magic.unlink(missing_ok=True)
    else:
        magic.write_text(MAGIC)
    return {"PYTHONPATH": ":".join(filter(None, [str(folder), existing]))}
