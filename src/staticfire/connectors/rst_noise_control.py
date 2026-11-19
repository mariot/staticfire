from staticfire.connector_vendors import ConnectorSpec

CALLS = ["/rstcloud/v1/benign/lookup"]
ENV = {"RST_NOISE_CONTROL_API_KEY": "staticfire-fake-key"}

SPECS = [
    ConnectorSpec(
        recipe="rst-noise-control",
        connector="internal-enrichment/rst-noise-control",
        env=lambda fake: ENV,
        enrich=("IPv4-Addr", "203.0.113.201"),
        expected_types={"ipv4-addr"},
        calls=CALLS,
        description="a public resolver address is known noise (Drop): labelled and scored down",
    ),
    ConnectorSpec(
        recipe="rst-noise-control-domain",
        connector="internal-enrichment/rst-noise-control",
        env=lambda fake: ENV,
        enrich=("Domain-Name", "staticfire-noise.example.com"),
        expected_types={"domain-name"},
        calls=CALLS,
        description="a hosting domain is noise to score down (Change Score), labelled",
    ),
]
