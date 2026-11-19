from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="pgl-yoyo",
    connector="external-import/pgl-yoyo",
    expected_types={"indicator", "identity"},
    calls=["/pgl-yoyo/adservers/serverlist.php", "/pgl-yoyo/adservers/iplist.php"],
    description="the four blocklists (tracker and other ad server hostnames and addresses) "
    "become indicators attributed to the list's maintainer; invalid lines are dropped",
)
