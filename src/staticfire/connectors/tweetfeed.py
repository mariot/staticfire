from staticfire.connector_vendors import ConnectorSpec

SPEC = ConnectorSpec(
    recipe="tweetfeed",
    connector="external-import/tweetfeed",
    env=lambda fake: {"TWEETFEED_DAYS_BACK_IN_TIME": "2"},
    expected_types={"ipv4-addr", "domain-name", "url", "file", "indicator"},
    calls=["/github/0xDanielLopez/TweetFeed/master/"],
    opens_work=False,  # it writes through the API and sends no bundle
    description="daily IOC CSV files from the GitHub fake become observables and indicators",
)
