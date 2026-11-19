from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="hygiene",
    connector="internal-enrichment/hygiene",
    enrich=("IPv4-Addr", "8.8.8.8"),
    expected_types={"ipv4-addr"},
    description="a public DNS resolver is found in the bundled MISP warning lists: labelled and "
    "scored down (no vendor: the lists ship with pymispwarninglists)",
)
