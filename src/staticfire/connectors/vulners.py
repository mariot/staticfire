import random

from staticfire.connector_vendors import ConnectorSpec


def _vulnerability(cti) -> str:
    name = f"CVE-2021-{random.randint(10000, 99999)}"
    return cti.graphql(
        "mutation ($input: VulnerabilityAddInput!) { vulnerabilityAdd(input: $input) { id } }",
        {"input": {"name": name}},
    )["vulnerabilityAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="vulners",
    connector="internal-enrichment/vulners",
    env=lambda fake: {
        "VULNERS_API_KEY": "staticfire-fake-key",
        # the Vulners SDK builds its transport apart from the proxy variables
        "VULNERS_API_BASE_URL": fake.https_url("vulners"),
    },
    proxy=False,
    enrich=_vulnerability,
    expected_types={"vulnerability", "malware", "relationship:exploits"},
    calls=["/vulners/api/v4/stix/bundle"],
    description="a CVE vulnerability receives the STIX bundle Vulners builds for it",
)
