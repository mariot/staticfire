from staticfire.connector_vendors import ConnectorSpec


def _wallet(cti) -> str:
    """A Bitcoin address as a Cryptocurrency-Wallet observable."""
    return cti.graphql(
        """mutation ($value: String!) {
             stixCyberObservableAdd(type: "Cryptocurrency-Wallet",
               CryptocurrencyWallet: { value: $value }) { id } }""",
        {"value": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"},
    )["stixCyberObservableAdd"]["id"]


SPEC = ConnectorSpec(
    recipe="sochain",
    connector="internal-enrichment/sochain",
    enrich=_wallet,
    expected_types={"note", "identity"},
    calls=["/sochain/api/v3/address_summary/", "/sochain/api/v3/address_poisoning/"],
    description="a Bitcoin wallet gets its balance and activity description and an address "
    "poisoning note listing the look-alike senders",
)
