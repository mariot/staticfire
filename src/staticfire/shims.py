"""A ``sitecustomize`` making a connector's test environment look like its production one,
without touching its code.

* certifi answers the proxy's bundle (``SSL_CERT_FILE``): code passing ``verify=True`` to
  ``requests.Session.send`` validates against certifi whatever ``REQUESTS_CA_BUNDLE`` says, as
  the real vendor's certificate would pass.
* ``rabbitmq`` resolves to ``MQ_HOST``: OpenCTI advertises its RabbitMQ by its Docker name,
  which a connector deployed next to it resolves; one taking the advertised settings over its
  helper's (diode-import) would not reach it from this machine.
"""

from __future__ import annotations

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


def env(existing: str | None = None) -> dict[str, str]:
    """``PYTHONPATH`` putting the shim first (before ``existing``)."""
    folder = STATE_DIR / "shims"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "sitecustomize.py").write_text(SITECUSTOMIZE)
    return {"PYTHONPATH": ":".join(filter(None, [str(folder), existing]))}
