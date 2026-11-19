import random

from staticfire.connector_vendors import ConnectorSpec


def _new_address(cti) -> str:
    """A public address nobody enriched yet: the first enrichment marks the observable with the
    TLP of the threat, which a second one would then refuse above the maximum TLP."""
    address = f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return cti.create_observable("IPv4-Addr", address)["id"]


SPEC = ConnectorSpec(
    recipe="orange-cyberdefense-enrichment-v3",
    connector="internal-enrichment/orange-cyberdefense-enrichment-v3",
    env=lambda fake: {"OCD_ENRICH_DATALAKE_TOKEN": "staticfire-fake-key"},
    enrich=_new_address,
    expected_types={"indicator", "note", "malware", "relationship:based-on"},
    calls=["/orange-cyberdefense/api/v3/mrti/threats/lookup/"],
    description="a threat found in Datalake enriches an address with its score, labels, "
    "external reference, summary note and related malware",
)
