from staticfire.connector_vendors import ConnectorSpec


def _mac_address(cti) -> str:
    return cti.graphql(
        """mutation { stixCyberObservableAdd(type: "Mac-Addr",
             MacAddr: { value: "f0:18:98:11:22:33" }) { id } }"""
    )["stixCyberObservableAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="macadress",
    connector="internal-enrichment/macadress",
    env=lambda fake: {"MACADRESS_API_KEY": "mk_staticfire-fake-key"},
    enrich=_mac_address,
    expected_types={"mac-addr", "identity", "note", "relationship:related-to"},
    calls=["/macadress/v1/mac/"],
    description="a MAC address gets its labels and description, its registered vendor "
    "organization and an analysis note",
)
