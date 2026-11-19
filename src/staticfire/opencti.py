"""Thin OpenCTI GraphQL client: what a connector test needs to observe.

Connectors report their runs as *works* (status, completed number, messages, errors); what they
ingested is read back through the knowledge queries.
"""

from __future__ import annotations

import json

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

    def reset_state(self, connector_id: str) -> None:
        """Forget a connector's state (last run...), if the connector is known."""
        try:
            self.graphql(
                "mutation ($id: ID!) { resetStateConnector(id: $id) { id } }",
                {"id": connector_id},
            )
        except OpenCTIError:
            pass  # never registered yet

    def changed_since(
        self, since_iso: str, creator_id: str | None = None, first: int = 500
    ) -> list[dict]:
        """Objects and relationships created or updated since a date (by a user): what a run
        ingested. (A work's touchedElements are only recorded for investigation enrichments.)
        """
        conditions = [{"key": ["updated_at"], "values": [since_iso], "operator": "gt"}]
        if creator_id:
            conditions.append({"key": ["creator_id"], "values": [creator_id], "operator": "eq"})
        filters = {"mode": "and", "filters": conditions, "filterGroups": []}
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
        sightings = self.graphql(
            """query ($filters: FilterGroup, $first: Int) {
                 stixSightingRelationships(filters: $filters, first: $first) {
                   edges { node { entity_type } } } }""",
            {"filters": filters, "first": first},
        )["stixSightingRelationships"]["edges"]
        return [e["node"] for e in objects + relationships + sightings]

    # -- users --

    def user_by_name(self, name: str) -> dict | None:
        edges = self.graphql(
            """query ($search: String) { users(search: $search, first: 50) {
                 edges { node { id name } } } }""",
            {"search": name},
        )["users"]["edges"]
        return next((e["node"] for e in edges if e["node"]["name"] == name), None)

    def service_user(self, name: str, group: str = "Connectors") -> tuple[str, str]:
        """(id, token) of a service account in ``group``: a connector run under its own user
        makes what it ingested attributable (objects keep every creator that upserted them).

        A token is only shown once, so an existing user gets a new one.
        """
        user = self.user_by_name(name)
        if user is None:
            groups = self.graphql(
                """query ($search: String) { groups(search: $search) {
                     edges { node { id name } } } }""",
                {"search": group},
            )["groups"]["edges"]
            group_id = next(e["node"]["id"] for e in groups if e["node"]["name"] == group)
            user = self.graphql(
                """mutation ($input: UserAddInput!) { userAdd(input: $input) { id name } }""",
                {
                    "input": {
                        "name": name,
                        "user_email": f"{name}@staticfire.test",
                        "user_service_account": True,
                        "prevent_default_groups": True,
                        "groups": [group_id],
                    }
                },
            )["userAdd"]
        token = self.graphql(
            """mutation ($id: ID!, $input: UserTokenAddInput!) {
                 userAdminTokenAdd(userId: $id, input: $input) { plaintext_token } }""",
            {"id": user["id"], "input": {"name": "staticfire", "duration": "DAYS_30"}},
        )["userAdminTokenAdd"]["plaintext_token"]
        return user["id"], token

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

    def label(self, value: str) -> str:
        """The id of a label (created if needed)."""
        return self.graphql(
            "mutation ($input: LabelAddInput!) { labelAdd(input: $input) { id } }",
            {"input": {"value": value}},
        )["labelAdd"]["id"]

    def create_observable(
        self, observable_type: str, value: str, labels: list[str] | None = None
    ) -> dict:
        key = {
            "IPv4-Addr": "IPv4Addr",
            "IPv6-Addr": "IPv6Addr",
            "Domain-Name": "DomainName",
            "Url": "Url",
            "Email-Addr": "EmailAddr",
            "Hostname": "Hostname",
        }[observable_type]
        return self.graphql(
            f"""mutation ($value: String!, $labels: [String]) {{
                  stixCyberObservableAdd(type: "{observable_type}", objectLabel: $labels,
                                         {key}: {{ value: $value }}) {{
                    id standard_id entity_type observable_value }} }}""",
            {"value": value, "labels": labels or []},
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

    def upload_import(self, file_name: str, content: bytes, mime: str) -> dict:
        """Upload a global import file, without triggering any import; the File (id, name)."""
        operations = {
            "query": "mutation ($file: Upload!) { uploadImport(file: $file) { id name } }",
            "variables": {"file": None},
        }
        self.http.cookies.clear()
        # Built apart from the client: its JSON content type would replace the multipart one
        request = httpx.Request(
            "POST",
            f"{self.url}/graphql",
            headers={
                "Authorization": self.http.headers["Authorization"],
                "apollo-require-preflight": "true",
            },
            data={
                "operations": json.dumps(operations),
                "map": json.dumps({"0": ["variables.file"]}),
            },
            files={"0": (file_name, content, mime)},
        )
        response = self.http.send(request)
        if response.status_code >= 400:
            raise OpenCTIError(f"upload {response.status_code}: {response.text[:500]}")
        payload = response.json()
        if payload.get("errors"):
            raise OpenCTIError(f"upload errors: {payload['errors'][:3]}")
        return payload["data"]["uploadImport"]

    def ask_import(self, file_id: str, connector_id: str) -> dict:
        """Have one import connector process an uploaded file, straight into the knowledge."""
        return self.graphql(
            """mutation ($file: ID!, $connector: String) {
                 askJobImport(fileName: $file, connectorId: $connector, bypassValidation: true) {
                   id name } }""",
            {"file": file_id, "connector": connector_id},
        )["askJobImport"]

    def ask_export(self, object_ids: list[str], mime: str, entity_type: str) -> list[dict]:
        """Export a list of objects to a format: every connector handling it gets a work."""
        return self.graphql(
            """mutation ($input: StixCoreObjectsExportAskInput!) {
                 stixCoreObjectsExportAsk(input: $input) { id name } }""",
            {
                "input": {
                    "format": mime,
                    "exportType": "full",
                    # declared optional, but OpenCTI fails without them
                    "contentMaxMarkings": [],
                    "fileMarkings": [],
                    "exportContext": {"entity_type": entity_type},
                    "selectedIds": object_ids,
                }
            },
        )["stixCoreObjectsExportAsk"]

    def ask_entity_export(self, object_id: str, mime: str) -> list[dict]:
        """Export one object (a report as a PDF, an intrusion set as a layer...)."""
        return self.graphql(
            """mutation ($id: ID!, $input: ExportAskInput!) { stixCoreObjectEdit(id: $id) {
                 exportAsk(input: $input) { id name } } }""",
            {
                "id": object_id,
                "input": {
                    "format": mime,
                    "exportType": "full",
                    "contentMaxMarkings": [],
                    "fileMarkings": [],
                },
            },
        )["stixCoreObjectEdit"]["exportAsk"]

    def export_files(self, entity_type: str, object_id: str | None = None) -> list[dict]:
        """Files exported for a list of ``entity_type``, or for one object."""
        if object_id:
            data = self.graphql(
                """query ($id: String!) { stixCoreObject(id: $id) {
                     exportFiles(first: 100) { edges { node { id name size } } } } }""",
                {"id": object_id},
            )["stixCoreObject"]["exportFiles"]
        else:
            data = self.graphql(
                """query ($type: String!) {
                     stixCoreObjectsExportFiles(first: 100, exportContext: {entity_type: $type}) {
                       edges { node { id name size } } } }""",
                {"type": entity_type},
            )["stixCoreObjectsExportFiles"]
        return [edge["node"] for edge in data["edges"]]

    def create_report(self, name: str, object_ids: list[str]) -> dict:
        return self.graphql(
            """mutation ($input: ReportAddInput!) { reportAdd(input: $input) {
                 id standard_id entity_type } }""",
            {
                "input": {
                    "name": name,
                    "published": "2026-01-01T00:00:00.000Z",
                    "description": "staticfire export test",
                    "objects": object_ids,
                }
            },
        )["reportAdd"]

    def add_uses_attack_pattern(self, source_id: str, mitre_id: str, name: str) -> dict:
        """Create (or reuse) an attack pattern and a "uses" relationship to it."""
        pattern = self.graphql(
            """mutation ($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) {
                 id } }""",
            {"input": {"name": name, "x_mitre_id": mitre_id}},
        )["attackPatternAdd"]
        return self.graphql(
            """mutation ($input: StixCoreRelationshipAddInput!) {
                 stixCoreRelationshipAdd(input: $input) { id } }""",
            {
                "input": {
                    "fromId": source_id,
                    "toId": pattern["id"],
                    "relationship_type": "uses",
                }
            },
        )["stixCoreRelationshipAdd"]

    def create_intrusion_set(self, name: str) -> dict:
        return self.graphql(
            """mutation ($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) {
                 id standard_id entity_type } }""",
            {"input": {"name": name, "description": "staticfire export test"}},
        )["intrusionSetAdd"]

    def live_stream(self, name: str = "staticfire", filters: dict | None = None) -> str:
        """The id of a live stream (every change, or what ``filters`` keep), created once."""
        edges = self.graphql(
            """query ($search: String) { streamCollections(search: $search) {
                 edges { node { id name } } } }""",
            {"search": name},
        )["streamCollections"]["edges"]
        if found := next((e["node"]["id"] for e in edges if e["node"]["name"] == name), None):
            return found
        return self.graphql(
            """mutation ($input: StreamCollectionAddInput!) {
                 streamCollectionAdd(input: $input) { id } }""",
            {
                "input": {
                    "name": name,
                    "stream_live": True,
                    "description": "staticfire",
                    # without filters OpenCTI answers 500 to the stream's readers
                    "filters": json.dumps(
                        filters or {"mode": "and", "filters": [], "filterGroups": []}
                    ),
                }
            },
        )["streamCollectionAdd"]["id"]

    def create_indicator(
        self,
        name: str,
        pattern: str,
        main_type: str,
        pattern_type: str = "stix",
        labels: list[str] | None = None,
    ) -> dict:
        return self.graphql(
            """mutation ($input: IndicatorAddInput!) { indicatorAdd(input: $input) {
                 id standard_id entity_type } }""",
            {
                "input": {
                    "name": name,
                    "pattern": pattern,
                    "pattern_type": pattern_type,
                    "objectLabel": labels or [],
                    "x_opencti_main_observable_type": main_type,
                    "x_opencti_score": 80,
                }
            },
        )["indicatorAdd"]
