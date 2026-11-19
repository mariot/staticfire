from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="ransomlook",
    connector="external-import/ransomlook",
    env=lambda fake: {"RANSOMLOOK_INITIAL_HISTORY_DAYS": "3"},
    expected_types={
        "report",
        "incident",
        "intrusion-set",
        "identity",
        "infrastructure",
        "note",
        "url",
        "domain-name",
        "cryptocurrency-wallet",
        "artifact",
        "threat-actor",
        "relationship:related-to",
    },
    calls=[
        "/ransomlook/api/posts",
        "/ransomlook/api/group/",
        "/ransomlook/api/post/",
        "/ransomlook/api/actors/",
        "/ransomlook/api/notes/",
        "/ransomlook/api/crypto/",
        "/ransomlook/api/torrent/health",
        "/ransomlook/api/leaks/leaks",
    ],
    description="claims become incidents and reports with group profiles, infrastructure, notes, "
    "wallets, torrents, leaks and capture artifacts (screenshots, page sources)",
)
