"""Catalog and asset collectors: they import a dataset (ofapi's) into the platform.

No agent and no inject: the collector runs once against the fake source and the platform must
end up with exactly what the dataset implies (and nothing it excludes). ``checks`` is polled
until it passes or the time runs out.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from staticfire.fakes import Ofapi
from staticfire.openaev import OpenAEV, OpenAEVError

Check = tuple[str, bool, object]


@dataclass
class CatalogCollector:
    recipe: str
    collector: str  # directory in the collectors repository
    env: Callable[[Ofapi], dict[str, str]]
    checks: Callable[[OpenAEV, str], list[Check]]  # (api, collector id)
    # Source paths the collector must have fetched from the fake
    calls: list[str]
    timeout: float = 240
    # Send its HTTP(S) through the proxy to ofapi (hardcoded vendor hosts, SDKs)
    proxy: bool = False
    description: str = ""


def _by(items: list[dict], key: str) -> dict:
    return {item.get(key): item for item in items or []}


# -- MITRE ATLAS --


def _atlas_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    patterns = _by(api.get("/api/attack_patterns"), "attack_pattern_external_id")
    phases = _by(api.get("/api/kill_chain_phases"), "phase_external_id")
    parent = patterns.get("AML.T0000")
    sub = patterns.get("AML.T0000.000")
    return [
        (
            "tactics imported as kill chain phases",
            {"AML.TA0002", "AML.TA0000"} <= phases.keys(),
            sorted(k for k in phases if str(k).startswith("AML")),
        ),
        (
            "techniques imported",
            {"AML.T0000", "AML.T0000.000", "AML.T0040"} <= patterns.keys(),
            sorted(k for k in patterns if str(k).startswith("AML")),
        ),
        (
            "sub-technique linked to its parent",
            bool(
                parent
                and sub
                and sub.get("attack_pattern_parent") == parent.get("attack_pattern_id")
            ),
            sub,
        ),
        (
            "technique linked to its tactic",
            bool(
                parent
                and phases.get("AML.TA0002", {}).get("phase_id")
                in (parent.get("attack_pattern_kill_chain_phases") or [])
            ),
            parent,
        ),
        ("revoked technique skipped", "AML.T9999" not in patterns, None),
    ]


MITRE_ATLAS = CatalogCollector(
    recipe="mitre-atlas",
    collector="mitre-atlas",
    env=lambda fake: {"COLLECTOR_STIX_URL": fake.http_url("mitre-atlas/stix-atlas.json")},
    checks=_atlas_checks,
    calls=["/mitre-atlas/stix-atlas.json"],
    description="a 2-tactic ATLAS bundle with a sub-technique and a revoked technique",
)

# -- NVD --


def _cve(api: OpenAEV, external_id: str) -> dict | None:
    try:
        return api.get(f"/api/cves/external-id/{external_id}") or None
    except OpenAEVError:
        return None


def _nvd_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    first, second, skipped = (
        _cve(api, cve) for cve in ("CVE-2099-90001", "CVE-2099-90002", "CVE-2099-90003")
    )
    cwes = [c.get("cwe_external_id") for c in (first or {}).get("vulnerability_cwes") or []]
    return [
        (
            "CVE with CVSS v3.1 imported with its score",
            bool(first) and first.get("vulnerability_cvss_v31") == 9.8,
            first,
        ),
        ("its weakness imported as a CWE", "CWE-79" in cwes, cwes),
        ("second CVE imported", bool(second), second),
        ("CVE without CVSS v3.1 skipped", skipped is None, skipped),
    ]


NVD_NIST_CVE = CatalogCollector(
    recipe="nvd-nist-cve",
    collector="nvd-nist-cve",
    env=lambda fake: {
        "NVDNISTCVE_API_BASE_URL": fake.http_url("nvd/rest/json"),
        "NVDNISTCVE_API_KEY": "staticfire-fake-key",
    },
    checks=_nvd_checks,
    calls=["/nvd/rest/json/cves/2.0"],
    description="3 CVEs, one without CVSS v3.1",
)

# -- OpenAEV payload repository --


def _payload_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    found = api.post("/api/payloads/search", {"page": 0, "size": 50, "textSearch": "ofapi"})
    # Search results leave out the tags: read each payload
    payloads = {
        p.get("payload_external_id"): api.get(f"/api/payloads/{p['payload_id']}")
        for p in (found or {}).get("content", [])
    }
    tags = {t.get("tag_id"): t.get("tag_name") for t in api.get("/api/tags") or []}

    def tag_names(external_id: str) -> set[str]:
        payload = payloads.get(external_id) or {}
        return {tags.get(t) for t in payload.get("payload_tags") or []}

    native = tag_names("ofapi-payload-native-0001")
    community = tag_names("ofapi-payload-community-0001")
    return [
        (
            "both payloads imported",
            {"ofapi-payload-native-0001", "ofapi-payload-community-0001"} <= payloads.keys(),
            sorted(payloads),
        ),
        (
            "source tag on imported payloads",
            "source:openaev-datasets" in native and "source:openaev-datasets" in community,
            {"native": native, "community": community},
        ),
        (
            "native tag only on the native payload",
            "type:native" in native and "type:native" not in community,
            {"native": native, "community": community},
        ),
    ]


OPENAEV_PAYLOADS = CatalogCollector(
    recipe="openaev-payloads",
    collector="openaev",
    # The collector appends file names to the prefix: it must end with a slash
    env=lambda fake: {
        "OPENAEV_URL_PREFIX": fake.http_url("openaev-payloads") + "/",
        # Required by its settings, although its README documents a default
        "COLLECTOR_NAME": "OpenAEV Datasets",
    },
    checks=_payload_checks,
    calls=["/openaev-payloads/manifest.json"],
    description="a manifest with a native and a community Command payload",
)

# -- AWS EC2 --


def _aws_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    endpoints = _by(api.endpoints(), "asset_external_reference")
    running = endpoints.get("i-0ofapi000000000001") or {}
    ips = set(running.get("endpoint_ips") or running.get("asset_ips") or [])
    return [
        (
            "running instance imported as an endpoint",
            bool(running),
            running
            and {
                k: running.get(k)
                for k in ("asset_name", "asset_external_reference", "endpoint_platform")
            },
        ),
        ("its private and public IPs", {"10.0.1.10", "198.51.100.10"} <= ips, sorted(ips)),
        ("terminated instance skipped", "i-0ofapi000000000002" not in endpoints, None),
        ("instance without any IP skipped", "i-0ofapi000000000003" not in endpoints, None),
    ]


AWS_RESOURCES = CatalogCollector(
    recipe="aws-resources",
    collector="aws-resources",
    env=lambda fake: {
        # botocore honours per-service endpoint overrides
        "AWS_ENDPOINT_URL_EC2": fake.http_url("aws-ec2"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "COLLECTOR_AWS_ACCESS_KEY_ID": "AKIASTATICFIREFAKE",
        "COLLECTOR_AWS_SECRET_ACCESS_KEY": "staticfire-fake-secret",
        "COLLECTOR_AWS_SESSION_TOKEN": "",
        "COLLECTOR_AWS_ASSUME_ROLE_ARN": "",
        "COLLECTOR_AWS_REGIONS": "us-east-1",
    },
    checks=_aws_checks,
    calls=["/aws-ec2"],
    description="3 EC2 instances: running, terminated, stopped without IP",
)

SPECS: dict[str, CatalogCollector] = {
    spec.recipe: spec for spec in [MITRE_ATLAS, NVD_NIST_CVE, OPENAEV_PAYLOADS, AWS_RESOURCES]
}
