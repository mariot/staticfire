from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="mattermost",
    connector="external-import/mattermost",
    env=lambda fake: {
        "MATTERMOST_TOKEN": "staticfire-fake-token",
        "MATTERMOST_CHANNEL_IDS": "abcdefghij0123456789klmnop",
    },
    expected_types={"channel", "media-content", "identity", "relationship:related-to"},
    calls=["/mattermost/api/v4/channels/", "/mattermost/api/v4/files/"],
    description=(
        "a channel's posts (thread reply, file attachment, deleted post skipped) become "
        "a channel, authors and media-content observables"
    ),
)
