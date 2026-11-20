from staticfire.connector_vendors import ConnectorSpec

_ENV = {
    "INTELIX_CLIENT_ID": "staticfire-client",
    "INTELIX_CLIENT_SECRET": "staticfire-fake-secret",
    "INTELIX_REGION_URI": "https://us.api.labs.sophos.com",
}

# The connector writes an external reference and a label through the API: no bundle is sent
SPECS = [
    ConnectorSpec(
        recipe="sophoslabs-intelix",
        connector="internal-enrichment/sophoslabs-intelix",
        env=lambda fake: _ENV,
        enrich=("IPv4-Addr", "93.184.216.34"),
        calls=["/sophoslabs-intelix/oauth2/token", "/sophoslabs-intelix/lookup/ips/v1/"],
        description="an address is looked up after the OAuth token and gets an external "
        "reference and a category label through the API (no bundle)",
    ),
    ConnectorSpec(
        recipe="sophoslabs-intelix-url",
        connector="internal-enrichment/sophoslabs-intelix",
        env=lambda fake: _ENV,
        enrich=("Url", "https://login.staticfire-example.com/verify"),
        calls=["/sophoslabs-intelix/lookup/urls/v1/"],
        description="a URL gets its security category label and an external reference",
    ),
    ConnectorSpec(
        recipe="sophoslabs-intelix-file",
        connector="internal-enrichment/sophoslabs-intelix",
        env=lambda fake: _ENV,
        enrich=("StixFile", "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592"),
        calls=["/sophoslabs-intelix/lookup/files/v1/"],
        description="a file hash gets its reputation label (malware) and an external reference",
    ),
]
