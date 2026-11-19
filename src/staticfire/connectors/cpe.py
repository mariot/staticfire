from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="cpe",
    connector="external-import/cpe",
    env=lambda fake: {
        "CPE_API_KEY": "staticfire-fake-key",
        "CPE_BASE_URL": "https://cpe-api.nvd.staticfire.test/rest/json/cpes/2.0",
    },
    expected_types={"software"},
    calls=["/nvd-cpe/rest/json/cpes/2.0"],
    timeout=420,
    description="the paginated CPE dictionary becomes software (hardware, deprecated skipped)",
)
