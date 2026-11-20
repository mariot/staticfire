"""vt-py (the VirusTotal client of some connectors) ignores HTTP(S)_PROXY unless asked
(``trust_env``) and has no setting for another host: its requests would reach the real
VirusTotal. A ``vt`` package placed first on ``PYTHONPATH`` loads the real one and turns
``trust_env`` on by default, so the connector runs unchanged through the proxy."""

from staticfire.config import STATE_DIR

VT_SHIM = """\
import sys

_here = __file__.rsplit("/vt/", 1)[0]
sys.path[:] = [p for p in sys.path if p != _here]
del sys.modules[__name__]
import vt as _real  # noqa: E402  (the real package: ours is out of the path)
from vt import client as _client  # noqa: E402

_init = _client.Client.__init__


def _trusting_init(self, *args, **kwargs):
    kwargs.setdefault("trust_env", True)
    _init(self, *args, **kwargs)


_client.Client.__init__ = _trusting_init
sys.modules[__name__] = _real
"""


def vt_proxy_env() -> dict[str, str]:
    """``PYTHONPATH`` putting the ``vt`` shim first."""
    folder = STATE_DIR / "vt-shim"
    (folder / "vt").mkdir(parents=True, exist_ok=True)
    (folder / "vt" / "__init__.py").write_text(VT_SHIM)
    return {"PYTHONPATH": str(folder)}
