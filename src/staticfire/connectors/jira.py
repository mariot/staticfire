import uuid

from staticfire.connector_vendors import ConnectorSpec


def _incident(cti) -> list[str]:
    """A new incident, one of the types the connector turns into a Jira issue."""
    name = f"staticfire incident {uuid.uuid4().hex[:8]}"
    cti.graphql(
        """mutation ($input: IncidentAddInput!) { incidentAdd(input: $input) { id } }""",
        {"input": {"name": name, "description": "staticfire stream test"}},
    )
    return [name]


SPEC = ConnectorSpec(
    recipe="jira",
    connector="stream/jira",
    env=lambda fake: {
        "JIRA_URL": "https://staticfire.atlassian.net",
        "JIRA_LOGIN_EMAIL": "staticfire@example.com",
        "JIRA_API_TOKEN": "staticfire-fake-key",
        "JIRA_PROJECT_KEY": "SF",
        "JIRA_ISSUE_TYPE_NAME": "Task",
    },
    stream=_incident,
    calls=["/jira/rest/api/2/issue"],
    description="a new incident becomes a Jira issue (summary, description) in the project",
)
