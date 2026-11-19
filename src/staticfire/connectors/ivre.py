from staticfire.connector_vendors import ConnectorSpec

_URL = "http://ivre.staticfire.test/cgi"
# every purpose (the defaults of IVRE: local MaxMind files, MongoDB) reads the web API
_ENV = {"IVRE_DB_URL": _URL, **{f"IVRE_DB_URL_{p}": _URL for p in ("DATA", "PASSIVE", "SCANS")}}
_CALLS = ["/ivre/cgi/ipdata/", "/ivre/cgi/passive", "/ivre/cgi/scans"]

SPECS = [
    ConnectorSpec(
        recipe="ivre",
        connector="internal-enrichment/ivre",
        env=lambda fake: _ENV,
        enrich=("IPv4-Addr", "185.220.101.38"),
        calls=_CALLS,
        description="an address is looked up in an IVRE instance (HTTP backend): GeoIP, "
        "passive DNS and certificates, scans; the objects are created through the API",
    ),
    ConnectorSpec(
        recipe="ivre-domain",
        connector="internal-enrichment/ivre",
        # the name the platform knows the connector by: renaming it between runs loses
        # the enrichment messages sent while it runs
        env=lambda fake: {**_ENV, "CONNECTOR_NAME": "staticfire ivre"},
        enrich=("Domain-Name", "staticfire-ivre.example.com"),
        calls=["/ivre/cgi/passive"],
        description="a domain is looked up in the passive DNS of an IVRE instance",
    ),
]
