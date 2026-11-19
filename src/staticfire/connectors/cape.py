from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cape",
    connector="external-import/cape",
    env=lambda fake: {
        "CAPE_API_URL": "https://cape.example.com/apiv2/",
        "CAPE_BASE_URL": "https://cape.example.com/",
        "CAPE_ENABLE_NETWORK_TRAFFIC": "true",
        "CAPE_ENABLE_REGISTRY_KEYS": "true",
    },
    expected_types={
        "report",
        "file",
        "indicator",
        "ipv4-addr",
        "domain-name",
        "process",
        "note",
        # a malware family only the first time it is seen (later ones link the existing one)
        "network-traffic",
        "windows-registry-key",
        "relationship:related-to",
        "relationship:resolves-to",
        "relationship:based-on",
    },
    timeout=300,
    calls=["/cape/apiv2/tasks/list", "/cape/apiv2/tasks/get/report/"],
    opens_work=False,  # it sends its bundles without a work
    description="reported sandbox tasks become a report with files, network, processes and notes",
)
