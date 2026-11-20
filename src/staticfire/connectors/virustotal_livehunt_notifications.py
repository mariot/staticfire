from staticfire.connector_vendors import ConnectorSpec
from staticfire.connectors._vt_proxy import vt_proxy_env

SPEC = ConnectorSpec(
    recipe="virustotal-livehunt-notifications",
    connector="external-import/virustotal-livehunt-notifications",
    env=lambda fake: {
        **vt_proxy_env(),
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_API_KEY": "staticfire-fake-key",
        # the compose file quotes these values: the quotes would become part of them
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_EXTENSIONS": "exe,dll",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_FILTER_WITH_TAG": "",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_UPLOAD_ARTIFACT": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_DELETE_NOTIFICATION": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_GET_MALWARE_CONFIG": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_FILE_INDICATORS": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_DOMAIN_NAME_INDICATORS": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_IP_INDICATORS": "true",
        "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_CREATE_URL_INDICATORS": "true",
    },
    expected_types={
        "incident",
        "file",
        "indicator",
        "domain-name",
        "ipv4-addr",
        "ipv6-addr",
        "url",
        "relationship:related-to",
        "relationship:based-on",
    },
    calls=[
        "/virustotal/api/v3/ioc_stream",
        "/virustotal/api/v3/intelligence/hunting_rulesets/",
    ],
    description="hunting notifications become alerts, files with their malware-config "
    "infrastructure, file and YARA indicators (samples are also uploaded as artifacts)",
)
