"""Thin client for the parts of the OpenAEV REST API a functional test needs.

Only plain HTTP and JSON: the responses are returned as the platform sends them, so a test can
assert on any field without this module having to model it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import httpx

# io.openaev.database.model.ExecutionStatus: DRAFT/QUEUING/EXECUTING/PENDING are progress states
TERMINAL_INJECT_STATUSES = {
    "EXECUTED",
    "PARTIAL",
    "ERROR",
    "MAYBE_PREVENTED",
    "MAYBE_PARTIAL_PREVENTED",
}
TERMINAL_EXERCISE_STATUSES = {"FINISHED", "CANCELED"}


class OpenAEVError(RuntimeError):
    def __init__(self, response: httpx.Response):
        self.status_code = response.status_code
        self.body = response.text[:2000]
        super().__init__(
            f"{response.request.method} {response.request.url.path} -> "
            f"{response.status_code}: {self.body}"
        )


class OpenAEV:
    def __init__(self, url: str, token: str, timeout: float = 30.0):
        self.url = url.rstrip("/")
        self.http = httpx.Client(
            base_url=self.url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    # -- plumbing --

    def request(self, method: str, path: str, **kwargs) -> Any:
        # A request carrying a cookie the platform set earlier is treated as a browser session
        # and a bodyless POST then fails its CSRF check (403): stay a pure bearer client
        self.http.cookies.clear()
        response = self.http.request(method, path, **kwargs)
        if response.status_code >= 400:
            raise OpenAEVError(response)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    def get(self, path: str, **params) -> Any:
        return self.request("GET", path, params=params or None)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, json=body)

    def put(self, path: str, body: Any = None) -> Any:
        return self.request("PUT", path, json=body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    # -- platform --

    def settings(self) -> dict:
        return self.get("/api/settings")

    def me(self) -> dict:
        return self.get("/api/me")

    # -- injectors, contracts, collectors, endpoints --

    def injectors(self) -> list[dict]:
        return self.get("/api/injectors")

    def injector(self, injector_id: str) -> dict:
        return self.get(f"/api/injectors/{injector_id}")

    def injector_contracts(self, injector_id: str) -> list[dict]:
        return self.get(f"/api/injectors/{injector_id}/injector_contracts")

    def injector_contract(self, contract_id: str) -> dict:
        return self.get(f"/api/injector_contracts/{contract_id}")

    def collectors(self) -> list[dict]:
        return self.get("/api/collectors")

    def collector(self, collector_id: str) -> dict:
        return self.get(f"/api/collectors/{collector_id}")

    def endpoints(self) -> list[dict]:
        return self.get("/api/endpoints")

    def endpoint(self, endpoint_id: str) -> dict:
        return self.get(f"/api/endpoints/{endpoint_id}")

    # -- documents --

    def upload_document(self, file_name: str, content: bytes, description: str = "") -> dict:
        """Upload a document (inject attachment); its name is the file name."""
        self.http.cookies.clear()
        response = self.http.post(
            "/api/documents",
            files={
                "input": (
                    None,
                    json.dumps({"document_description": description}),
                    "application/json",
                ),
                "file": (file_name, content, "application/octet-stream"),
            },
        )
        if response.status_code >= 400:
            raise OpenAEVError(response)
        return response.json()

    # -- atomic testings --

    def create_atomic_testing(self, payload: dict) -> dict:
        return self.post("/api/atomic-testings", payload)

    def atomic_testing(self, inject_id: str) -> dict:
        return self.get(f"/api/atomic-testings/{inject_id}")

    def update_atomic_testing(self, inject_id: str, payload: dict) -> dict:
        return self.put(f"/api/atomic-testings/{inject_id}", payload)

    def launch_atomic_testing(self, inject_id: str) -> dict:
        return self.post(f"/api/atomic-testings/{inject_id}/launch")

    def relaunch_atomic_testing(self, inject_id: str) -> dict:
        return self.post(f"/api/atomic-testings/{inject_id}/relaunch")

    def delete_atomic_testing(self, inject_id: str) -> None:
        self.delete(f"/api/atomic-testings/{inject_id}")

    def target_results(self, inject_id: str, target_id: str, target_type: str) -> list[dict]:
        return self.get(
            f"/api/atomic-testings/{inject_id}/target_results/{target_id}/types/{target_type}"
        )

    # -- injects --

    def inject(self, inject_id: str) -> dict:
        return self.get(f"/api/injects/{inject_id}")

    def inject_status(self, inject_id: str) -> dict:
        """Status with its global execution traces (what the injector reported)."""
        return self.get("/api/injects/status", injectId=inject_id)

    def inject_traces(self, inject_id: str, target_id: str, target_type: str) -> list[dict]:
        return self.get(
            "/api/injects/execution-traces",
            injectId=inject_id,
            targetId=target_id,
            targetType=target_type,
        )

    # -- expectations (the collector's view) --

    def expectations_for_source(self, source_id: str) -> list[dict]:
        """Agent DETECTION/PREVENTION expectations the source has not answered yet."""
        return self.get(f"/api/injects/expectations/assets/{source_id}")

    def expectation_traces(self, expectation_id: str, source_id: str) -> list[dict]:
        return self.get(
            "/api/inject-expectations-traces",
            injectExpectationId=expectation_id,
            sourceId=source_id,
        )

    # -- scenarios and simulations --

    def scenarios(self) -> list[dict]:
        return self.get("/api/scenarios")

    def scenario(self, scenario_id: str) -> dict:
        return self.get(f"/api/scenarios/{scenario_id}")

    def launch_scenario(self, scenario_id: str) -> dict:
        """Create a simulation from the scenario and start it (chained workflows included)."""
        return self.post(f"/api/scenarios/{scenario_id}/exercise/running")

    def exercise(self, exercise_id: str) -> dict:
        return self.get(f"/api/exercises/{exercise_id}")

    def exercise_injects(self, exercise_id: str) -> list[dict]:
        return self.get(f"/api/exercises/{exercise_id}/injects")

    def set_exercise_status(self, exercise_id: str, status: str) -> dict:
        return self.put(f"/api/exercises/{exercise_id}/status", {"exercise_status": status})


def wait_until(
    check: Callable[[], Any],
    timeout: float,
    interval: float = 3.0,
) -> tuple[bool, Any]:
    """Call ``check`` until it returns a truthy value; returns (succeeded, last value)."""
    deadline = time.monotonic() + timeout
    value = None
    while True:
        value = check()
        if value:
            return True, value
        if time.monotonic() >= deadline:
            return False, value
        time.sleep(interval)
