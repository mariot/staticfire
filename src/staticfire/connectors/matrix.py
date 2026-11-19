import shutil

from staticfire import config
from staticfire.connector_vendors import ConnectorSpec

STORE = config.STATE_DIR / "matrix-store"


def _env(fake) -> dict[str, str]:
    # nio keeps its sync token in this store: a run must not resume from the previous one
    shutil.rmtree(STORE, ignore_errors=True)
    return {
        # matrix-nio ignores proxy variables: the homeserver is ofapi itself
        "MATRIX_SERVER": fake.http_url("matrix"),
        "MATRIX_USER_ID": "@octi-bot:matrix.example.org",
        "MATRIX_PASSWORD": "staticfire-fake-password",
        "MATRIX_STORE_PATH": str(STORE),
    }


SPEC = ConnectorSpec(
    recipe="matrix",
    connector="external-import/matrix",
    env=_env,
    expected_types={"channel", "media-content", "identity", "relationship:related-to"},
    calls=["/matrix/_matrix/client/v3/sync"],
    proxy=False,
    description=(
        "the joined rooms' history (text, notice, thread reply, edit, image and file "
        "attachments) becomes channels, authors and media-content observables"
    ),
)
