from staticfire import config, ops
from staticfire.connector_vendors import ConnectorSpec

# What the extraction service names in its answer (ofapi's import_document_ai module)
TECHNIQUES = [
    ("T1078", "Valid Accounts"),
    ("T1566", "Phishing"),
    ("T1059", "Command and Scripting Interpreter"),
]


def _env(fake) -> dict[str, str]:
    # A platform holds the MITRE ATT&CK techniques: the connector swaps a technique of the
    # extraction for the platform's one when it knows it
    for name in config.list_profiles():
        if config.load_profile(name).opencti_url:
            cti = ops.cti_client(config.load_profile(name))
            for mitre_id, technique in TECHNIQUES:
                cti.graphql(
                    """mutation ($input: AttackPatternAddInput!) {
                         attackPatternAdd(input: $input) { id } }""",
                    {"input": {"name": technique, "x_mitre_id": mitre_id}},
                )
            break
    return {
        "IMPORT_DOCUMENT_AI_API_BASE_URL": "https://importdoc.ariane.filigran.io",
        "IMPORT_DOCUMENT_AI_API_KEY": "staticfire-fake-licence",
    }


SPEC = ConnectorSpec(
    recipe="import-document-ai",
    connector="internal-import-file/import-document-ai",
    env=_env,
    import_file=("staticfire-report.pdf", "/fixtures/report.pdf", "application/pdf"),
    expected_types={
        "report",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "location",
        "vulnerability",
        "ipv4-addr",
        "domain-name",
        "url",
        "email-addr",
        "file",
        "relationship:uses",
        "relationship:targets",
    },
    calls=["/import-document-ai/stix"],
    description="a PDF goes to the extraction service (legacy direct mode), its defanged STIX "
    "bundle is refanged and imported with a report holding the file; a technique the "
    "platform already knows is swapped for the platform's one",
)
