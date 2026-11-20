from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="sigmahq",
    connector="external-import/sigmahq",
    expected_types={"indicator", "attack-pattern", "vulnerability", "relationship:indicates"},
    calls=["/github/repos/SigmaHQ/sigma/releases/latest"],
    description="the latest SigmaHQ release package (zip of rules) becomes Sigma indicators "
    "linked to ATT&CK techniques and CVEs",
)
