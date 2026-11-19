import hashlib
import random
import uuid

from staticfire.connector_vendors import ConnectorSpec


def _report_with_iocs(cti) -> str:
    """A report whose description mentions every kind of indicator the connector extracts."""
    token = uuid.uuid4().hex[:8]
    ipv4 = f"203.0.{random.randint(114, 200)}.{random.randint(1, 254)}"
    ipv6 = f"2a00:1450:4007:{random.randint(1, 9999):x}::{random.randint(1, 9999):x}"
    description = (
        f"The campaign {token} used the command and control server {ipv4} (and {ipv6}), "
        f"the staging domain evil-{token}.example.org and the payload "
        f"https://dl-{token}.example.net/stage/update.exe. The dropper hashes are "
        f"{hashlib.md5(token.encode()).hexdigest()}, "
        f"{hashlib.sha1(token.encode()).hexdigest()} and "
        f"{hashlib.sha256(token.encode()).hexdigest()}. The internal host 10.20.30.40 "
        "only relayed the traffic."
    )
    return cti.graphql(
        """mutation ($input: ReportAddInput!) { reportAdd(input: $input) { id } }""",
        {
            "input": {
                "name": f"staticfire ioc extractor {token}",
                "published": "2026-01-01T00:00:00.000Z",
                "description": description,
            }
        },
    )["reportAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="ioc-extractor",
    connector="internal-enrichment/ioc-extractor",
    enrich=_report_with_iocs,
    expected_types={"report", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"},
    description="the observables written in a report's description (addresses, domain, URL, "
    "hashes) are extracted and attached to the report; the private address is skipped",
)
