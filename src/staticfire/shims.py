"""A ``sitecustomize`` making a connector's test environment look like its production one,
without touching its code.

* certifi answers the proxy's bundle (``SSL_CERT_FILE``): code passing ``verify=True`` to
  ``requests.Session.send`` validates against certifi whatever ``REQUESTS_CA_BUNDLE`` says, as
  the real vendor's certificate would pass.
* without libmagic on this machine (python-magic cannot load), a ``magic`` module using the
  file(1) command stands in for python-magic.
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

_getaddrinfo = socket.getaddrinfo


def _resolve(host, *args, **kwargs):
    if host == "rabbitmq" and os.environ.get("MQ_HOST"):
        host = os.environ["MQ_HOST"]
    return _getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _resolve
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
