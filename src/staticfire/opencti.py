"""Thin OpenCTI GraphQL client: what a connector test needs to observe.

Connectors report their runs as *works* (status, completed number, messages, errors); what they
ingested is read back through the knowledge queries.
"""

from __future__ import annotations

from typing import Any

import httpx

TERMINAL_WORK_STATUSES = {"complete"}


class OpenCTIError(RuntimeError):
    pass


class OpenCTI:
    def __init__(self, url: str, token: str, timeout: float = 60.0):
        self.url = url.rstrip("/")
        self.http = httpx.Client(
            base_url=self.url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        self.http.cookies.clear()
        response = self.http.post("/graphql", json={"query": query, "variables": variables or {}})
        if response.status_code >= 400:
            raise OpenCTIError(f"GraphQL {response.status_code}: {response.text[:1000]}")
        payload = response.json()
        if payload.get("errors"):
            raise OpenCTIError(f"GraphQL errors: {payload['errors'][:3]}")
        return payload["data"]

    # -- platform --

    def version(self) -> str:
        return self.graphql("query { about { version } }")["about"]["version"]

    # -- connectors and their works --

    def connectors(self) -> list[dict]:
        return self.graphql(
            """query { connectors { id name active connector_type connector_scope
                       updated_at built_in } }"""
        )["connectors"]

    def connector(self, connector_id: str) -> dict | None:
        return self.graphql(
            """query ($id: String!) { connector(id: $id) {
                   id name active connector_type connector_scope connector_state
                   works { id name status timestamp completed_number
                           messages { timestamp message }
                           errors { timestamp message source }
                           tracking { import_expected_number import_processed_number } } } }""",
            {"id": connector_id},
        )["connector"]

    def changed_since(self, since_iso: str, first: int = 500) -> list[dict]:
        """Objects and relationships created or updated since a date: what a run ingested.

        (A work's touchedElements are only recorded for investigation enrichments.)
        """
        filters = {
            "mode": "and",
            "filters": [{"key": ["updated_at"], "values": [since_iso], "operator": "gt"}],
            "filterGroups": [],
        }
        objects = self.graphql(
            """query ($filters: FilterGroup, $first: Int) {
                 stixCoreObjects(filters: $filters, first: $first) {
                   edges { node { entity_type representative { main } } } } }""",
            {"filters": filters, "first": first},
        )["stixCoreObjects"]["edges"]
        relationships = self.graphql(
            """query ($filters: FilterGroup, $first: Int) {
                 stixCoreRelationships(filters: $filters, first: $first) {
                   edges { node { entity_type relationship_type } } } }""",
            {"filters": filters, "first": first},
        )["stixCoreRelationships"]["edges"]
        return [e["node"] for e in objects] + [e["node"] for e in relationships]

    # -- knowledge --

    def stix_core_objects(
        self, search: str | None = None, types: list[str] | None = None, first: int = 50
    ) -> list[dict]:
        data = self.graphql(
            """query ($search: String, $types: [String], $first: Int) {
                 stixCoreObjects(search: $search, types: $types, first: $first) {
                   edges { node { id standard_id entity_type representative { main }
                                  createdBy { name } objectLabel { value }
                                  externalReferences { edges { node { source_name url } } }
                 } } } }""",
            {"search": search, "types": types, "first": first},
        )
        return [edge["node"] for edge in data["stixCoreObjects"]["edges"]]

    def stix_core_object(self, object_id: str) -> dict | None:
        return self.graphql(
            """query ($id: String!) { stixCoreObject(id: $id) {
                 id standard_id entity_type representative { main }
                 objectLabel { value }
                 stixCoreRelationships { edges { node { relationship_type
                     to { ... on StixObject { entity_type }
                          ... on StixCoreObject { representative { main } } } } } }
               } }""",
            {"id": object_id},
        )["stixCoreObject"]

    def create_observable(self, observable_type: str, value: str) -> dict:
        key = {
            "IPv4-Addr": "IPv4Addr",
            "IPv6-Addr": "IPv6Addr",
            "Domain-Name": "DomainName",
            "Url": "Url",
            "Email-Addr": "EmailAddr",
            "Hostname": "Hostname",
        }[observable_type]
        return self.graphql(
            f"""mutation ($value: String!) {{
                  stixCyberObservableAdd(type: "{observable_type}", {key}: {{ value: $value }}) {{
                    id standard_id entity_type observable_value }} }}""",
            {"value": value},
        )["stixCyberObservableAdd"]

    def create_file_observable(self, sha256: str, name: str | None = None) -> dict:
        return self.graphql(
            """mutation ($sha256: String!, $name: String) {
                 stixCyberObservableAdd(type: "StixFile",
                   StixFile: { hashes: [{ algorithm: "SHA-256", hash: $sha256 }], name: $name }) {
                   id standard_id entity_type observable_value } }""",
            {"sha256": sha256, "name": name},
        )["stixCyberObservableAdd"]

    def ask_enrichment(self, object_id: str, connector_id: str) -> dict:
        return self.graphql(
            """mutation ($id: ID!, $connectorId: ID!) {
                 stixCoreObjectEdit(id: $id) {
                   askEnrichment(connectorId: $connectorId) { id } } }""",
            {"id": object_id, "connectorId": connector_id},
        )["stixCoreObjectEdit"]["askEnrichment"]

    def push_bundle(self, bundle: dict, file_name: str = "staticfire.json") -> Any:
        """Upload a STIX bundle as a global import file (processed by import connectors)."""
        import json

        operations = {
            "query": "mutation ($file: Upload!) { uploadImport(file: $file) { id name } }",
            "variables": {"file": None},
        }
        self.http.cookies.clear()
        response = self.http.post(
            "/graphql",
            headers={"Content-Type": None},
            data={
                "operations": json.dumps(operations),
                "map": json.dumps({"0": ["variables.file"]}),
            },
            files={"0": (file_name, json.dumps(bundle).encode(), "application/json")},
        )
        if response.status_code >= 400:
            raise OpenCTIError(f"upload {response.status_code}: {response.text[:500]}")
        return response.json()
