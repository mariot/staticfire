"""Catalog and asset collectors: they import a dataset (ofapi's) into the platform.

No agent and no inject: the collector runs once against the fake source and the platform must
end up with exactly what the dataset implies (and nothing it excludes). ``checks`` is polled
until it passes or the time runs out.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

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
    # Run before the collector starts (api, fake): remove what an earlier run imported, so
    # that what the platform holds afterwards is this run's work
    setup: Callable[[OpenAEV, Ofapi], None] | None = None
    # Packages added to the component's virtualenv for the test, as a deployment behind a
    # proxy needs them (httplib2 ignores proxies without PySocks and goes direct)
    test_packages: list[str] = field(default_factory=list)
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


# -- Microsoft (Graph, ARM): the collectors hardcode their hosts, the proxy brings them to
# ofapi; the datasets (microsoft_graph_directory, azure_resource_manager) are read back from
# the fake to know what the platform must hold --

MS_TENANT = "6f1c2a4e-0b7d-4c55-9e3a-8d2f1b6c7a90"
MS_TOKEN = f"/microsoft-login/{MS_TENANT}/oauth2/v2.0/token"
GRAPH = "/microsoft-graph/v1.0"
ARM_SUBSCRIPTION = "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
ARM = f"/microsoft-sentinel/subscriptions/{ARM_SUBSCRIPTION}"


def _ms_credentials(prefix: str) -> dict[str, str]:
    return {
        f"{prefix}TENANT_ID": MS_TENANT,
        f"{prefix}CLIENT_ID": "3c9e5f21-7a44-4d0e-8b6b-2f9d0c1e4a77",
        f"{prefix}CLIENT_SECRET": "staticfire~fake.secret-value",
    }


def _graph_all(path: str) -> list[dict]:
    """Every item of a Graph listing on the fake, following its pages."""
    fake = Ofapi()
    items, url = [], path
    while url:
        page = fake.http.get(url).raise_for_status().json()
        items += page["value"]
        link = page.get("@odata.nextLink")
        url = GRAPH + link.split("/v1.0", 1)[1] if link else None
    return items


def _endpoint_tags(api: OpenAEV, found: dict) -> list[str]:
    """An endpoint's tag ids: the endpoint list leaves them out, its detail has them."""
    if not found.get("asset_id"):
        return []
    return api.endpoint(found["asset_id"]).get("asset_tags") or []


def _tag_names(api: OpenAEV) -> dict[str, str]:
    return {t["tag_id"]: t["tag_name"] for t in api.get("/api/tags") or []}


def _directory() -> tuple[list[dict], dict[str, list[dict]]]:
    groups = _graph_all(f"{GRAPH}/groups")
    return groups, {g["id"]: _graph_all(f"{GRAPH}/groups/{g['id']}/members") for g in groups}


def _people(members: list[dict]) -> tuple[list[dict], list[dict]]:
    """(users the collector imports, users it must leave out: guests, no mailbox)."""
    users = [m for m in members if m["@odata.type"] == "#microsoft.graph.user"]
    kept = [u for u in users if u.get("mail") and "#EXT#" not in u["userPrincipalName"]]
    return kept, [u for u in users if u not in kept]


def _entra_setup(api: OpenAEV, _fake: Ofapi) -> None:
    groups, members = _directory()
    emails = {u["mail"].lower() for m in members.values() for u in m if u.get("mail")}
    for player in api.get("/api/players") or []:
        if (player.get("user_email") or "").lower() in emails:
            api.delete(f"/api/players/{player['user_id']}")
    names = {g["displayName"] for g in groups}
    for team in api.get("/api/teams") or []:
        if team.get("team_name") in names:
            api.delete(f"/api/teams/{team['team_id']}")


def _entra_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    groups, members = _directory()
    teams = _by(api.get("/api/teams"), "team_name")
    players = {(p.get("user_email") or "").lower(): p for p in api.get("/api/players") or []}
    tags = _tag_names(api)
    checks: list[Check] = []
    for index, group in enumerate(groups):
        where = "on the second page of groups" if index >= 2 else "on the first page"
        checks.append(
            (f"group '{group['displayName']}' ({where}) imported as a team",
             group["displayName"] in teams, sorted(teams)[:30])
        )  # fmt: skip
    security = groups[0]
    team = teams.get(security["displayName"]) or {}
    kept, left_out = _people(members[security["id"]])
    for user in kept:
        player = players.get(user["mail"].lower())
        names = {tags.get(t) for t in (player or {}).get("user_tags") or []}
        wanted = {
            "source:microsoft-entra",
            "user-type:internal",
            f"department:{user['department'].lower()}",
            f"job-title:{user['jobTitle'].lower()}",
        }
        checks += [
            (f"member {user['mail']} imported with their names",
             bool(player) and (player["user_firstname"], player["user_lastname"])
             == (user["givenName"], user["surname"]), player),
            (f"member {user['mail']} in the group's team",
             bool(player) and player["user_id"] in (team.get("team_users") or []),
             team.get("team_users")),
            (f"member {user['mail']} tagged source, user type, department, job title",
             wanted <= names, sorted(filter(None, names))),
        ]  # fmt: skip
    for user in left_out:
        reason = "guest" if user.get("mail") else "account without mailbox"
        key = (user.get("mail") or user["userPrincipalName"]).lower()
        checks.append((f"{reason} {key} left out", key not in players, None))
    # Members are listed four per page: the fifth user is on the members' second page
    return checks


MICROSOFT_ENTRA = CatalogCollector(
    recipe="microsoft-entra",
    collector="microsoft-entra",
    env=lambda fake: {
        **_ms_credentials("COLLECTOR_MICROSOFT_ENTRA_"),
        "COLLECTOR_INCLUDE_EXTERNAL": "false",
        "COLLECTOR_PERIOD": "PT1H",
    },
    checks=_entra_checks,
    calls=[MS_TOKEN, f"{GRAPH}/groups"],
    proxy=True,
    setup=_entra_setup,
    description="3 Entra groups over 2 pages (Graph paging), members over 2 pages: internal "
    "users, a guest, an account without mailbox, a device",
)


INTUNE_GROUP = "SG-Intune Corporate Laptops"


def _intune_devices() -> list[dict]:
    return _graph_all(f"{GRAPH}/deviceManagement/managedDevices")


def _intune_setup(api: OpenAEV, _fake: Ofapi) -> None:
    ids = {d["id"] for d in _intune_devices()}
    for endpoint in api.endpoints() or []:
        if endpoint.get("asset_external_reference") in ids:
            api.delete(f"/api/endpoints/{endpoint['asset_id']}")


def _intune_device_checks(api: OpenAEV, devices: list[dict]) -> list[Check]:
    endpoints = _by(api.endpoints(), "asset_external_reference")
    tags = _tag_names(api)
    platforms = {"Windows": "Windows", "macOS": "MacOS", "iOS": "iOS"}
    checks: list[Check] = []
    for device in devices:
        found = endpoints.get(device["id"]) or {}
        names = {tags.get(t) for t in _endpoint_tags(api, found)}
        macs = {
            m.replace(":", "").replace("-", "").upper()
            for m in found.get("asset_mac_addresses") or []
        }
        label = f"{device['operatingSystem']} device {device['deviceName']}"
        checks += [
            (f"{label} imported as an endpoint", bool(found),
             found and {k: found.get(k) for k in ("asset_name", "endpoint_platform")}),
            (f"{label} platform {platforms[device['operatingSystem']]}",
             found.get("endpoint_platform") == platforms[device["operatingSystem"]],
             found.get("endpoint_platform")),
            (f"{label} Wi-Fi MAC address", device["wiFiMacAddress"] in macs, sorted(macs)),
            (f"{label} tagged source and compliance",
             {"source:microsoft-intune", f"compliance:{device['complianceState']}"} <= names,
             sorted(filter(None, names))),
        ]  # fmt: skip
    return checks


def _intune_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    # Two devices per page: the iOS device is on the second page
    return _intune_device_checks(api, _intune_devices())


MICROSOFT_INTUNE = CatalogCollector(
    recipe="microsoft-intune",
    collector="microsoft-intune",
    env=lambda fake: {
        **_ms_credentials("COLLECTOR_MICROSOFT_INTUNE_"),
        # Required by its settings although documented optional (its compose file passes
        # them empty)
        "COLLECTOR_MICROSOFT_INTUNE_DEVICE_FILTER": "",
        "COLLECTOR_MICROSOFT_INTUNE_DEVICE_GROUPS": "",
        "COLLECTOR_PERIOD": "PT1H",
    },
    checks=_intune_checks,
    calls=[MS_TOKEN, f"{GRAPH}/deviceManagement/managedDevices"],
    proxy=True,
    setup=_intune_setup,
    description="3 Intune managed devices over 2 pages (Windows, macOS, iOS)",
)


def _intune_group_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    groups, members = _directory()
    group = next(g for g in groups if g["displayName"] == INTUNE_GROUP)
    in_group = {m["deviceId"] for m in members[group["id"]] if m.get("deviceId")}
    devices = _intune_devices()
    endpoints = _by(api.endpoints(), "asset_external_reference")
    checks = _intune_device_checks(api, [d for d in devices if d["azureADDeviceId"] in in_group])
    for device in devices:
        if device["azureADDeviceId"] not in in_group:
            checks.append(
                (f"{device['operatingSystem']} device {device['deviceName']} (not in the "
                 "group) left out", device["id"] not in endpoints, None)
            )  # fmt: skip
    return checks


MICROSOFT_INTUNE_GROUPS = CatalogCollector(
    recipe="microsoft-intune-groups",
    collector="microsoft-intune",
    env=lambda fake: {
        **_ms_credentials("COLLECTOR_MICROSOFT_INTUNE_"),
        "COLLECTOR_MICROSOFT_INTUNE_DEVICE_GROUPS": INTUNE_GROUP,
        "COLLECTOR_MICROSOFT_INTUNE_DEVICE_FILTER": "",
        "COLLECTOR_PERIOD": "PT1H",
    },
    checks=_intune_group_checks,
    calls=[MS_TOKEN, f"{GRAPH}/groups", f"{GRAPH}/deviceManagement/managedDevices"],
    proxy=True,
    setup=_intune_setup,
    timeout=150,
    description=f"device group filter '{INTUNE_GROUP}': its 2 devices, not the third",
)


def _arm_vms() -> list[dict]:
    fake = Ofapi()
    path = f"{ARM}/providers/Microsoft.Compute/virtualMachines"
    return fake.http.get(path).raise_for_status().json()["value"]


def _arm_ips(vm: dict) -> set[str]:
    fake = Ofapi()
    ips = set()
    for interface in vm["properties"]["networkProfile"]["networkInterfaces"]:
        nic = fake.http.get("/microsoft-sentinel" + interface["id"]).json()
        for config in nic["properties"]["ipConfigurations"]:
            ips.add(config["properties"]["privateIPAddress"])
            if public := config["properties"].get("publicIPAddress"):
                address = fake.http.get("/microsoft-sentinel" + public["id"]).json()
                ips.add(address["properties"]["ipAddress"])
    return ips


def _azure_setup(api: OpenAEV, _fake: Ofapi) -> None:
    ids = {vm["id"] for vm in _arm_vms()}
    for endpoint in api.endpoints() or []:
        if endpoint.get("asset_external_reference") in ids:
            api.delete(f"/api/endpoints/{endpoint['asset_id']}")


def _azure_checks_for(groups: set[str]) -> Callable[[OpenAEV, str], list[Check]]:
    def checks(api: OpenAEV, _collector_id: str) -> list[Check]:
        endpoints = _by(api.endpoints(), "asset_external_reference")
        tags = _tag_names(api)
        result: list[Check] = []
        for vm in _arm_vms():
            group = vm["id"].split("/")[4]
            found = endpoints.get(vm["id"]) or {}
            state = vm["properties"]["provisioningState"]
            if state != "Succeeded" or group not in groups:
                why = f"provisioning {state}" if state != "Succeeded" else f"in {group}"
                result.append((f"VM {vm['name']} ({why}) left out", not found, None))
                continue
            os_type = vm["properties"]["storageProfile"]["osDisk"]["osType"]
            ips = set(found.get("asset_ips") or [])
            names = {tags.get(t) for t in _endpoint_tags(api, found)}
            wanted = {
                "source:microsoft-azure",
                f"location:{vm['location']}",
                f"resource-group:{group}",
            }
            result += [
                (f"VM {vm['name']} imported as an endpoint", bool(found),
                 found and {k: found.get(k) for k in ("asset_name", "asset_cloud_provider")}),
                (f"VM {vm['name']} platform {os_type}",
                 found.get("endpoint_platform") == os_type, found.get("endpoint_platform")),
                (f"VM {vm['name']} with its private and public IPs",
                 _arm_ips(vm) <= ips, sorted(ips)),
                (f"VM {vm['name']} tagged source, location, resource group",
                 wanted <= names, sorted(filter(None, names))),
            ]  # fmt: skip
        return result

    return checks


def _azure_env(groups: str) -> Callable[[Ofapi], dict[str, str]]:
    return lambda fake: {
        **_ms_credentials("COLLECTOR_MICROSOFT_AZURE_"),
        "COLLECTOR_MICROSOFT_AZURE_SUBSCRIPTION_ID": ARM_SUBSCRIPTION,
        "COLLECTOR_MICROSOFT_AZURE_RESOURCE_GROUPS": groups,
        "COLLECTOR_PERIOD": "PT1H",
    }


MICROSOFT_AZURE = CatalogCollector(
    recipe="microsoft-azure",
    collector="microsoft-azure",
    env=_azure_env("rg-staticfire-prod"),
    checks=_azure_checks_for({"rg-staticfire-prod"}),
    calls=[MS_TOKEN, f"{ARM}/resourceGroups/rg-staticfire-prod/providers/Microsoft.Compute"],
    proxy=True,
    setup=_azure_setup,
    description="resource group rg-staticfire-prod: a Linux VM with a public IP, a Windows "
    "VM, a failed VM; another group's VM must stay out",
)

MICROSOFT_AZURE_SUBSCRIPTION = CatalogCollector(
    recipe="microsoft-azure-subscription",
    collector="microsoft-azure",
    # An empty list of resource groups means every VM of the subscription
    env=_azure_env(""),
    checks=_azure_checks_for({"rg-staticfire-prod", "rg-staticfire-dev"}),
    calls=[MS_TOKEN, f"{ARM}/providers/Microsoft.Compute/virtualMachines"],
    proxy=True,
    setup=_azure_setup,
    timeout=150,
    description="no resource group given: every VM of the subscription (both groups)",
)


# -- Google Workspace (Admin SDK Directory through the proxy: admin.googleapis.com) --

GOOGLE_ADMIN = "/google-admin/admin/directory/v1"


def _google_service_account(fake: Ofapi) -> str:
    """A service account key file pointing at Google's real token URI (the proxy answers)."""
    import json

    from staticfire.injector_vendors import Context, gws_service_account

    info = json.loads(gws_service_account(Context(fake, "", Path("."))))
    info["token_uri"] = "https://oauth2.googleapis.com/token"
    return json.dumps(info)


def _google(path: str, field: str, **params) -> list[dict]:
    fake = Ofapi()
    items, token = [], ""
    while True:
        page = fake.http.get(f"{GOOGLE_ADMIN}{path}", params={**params, "pageToken": token})
        page = page.raise_for_status().json()
        items += page.get(field, [])
        token = page.get("nextPageToken")
        if not token:
            return items


def _google_setup(api: OpenAEV, _fake: Ofapi) -> None:
    emails = {u["primaryEmail"].lower() for u in _google("/users", "users", customer="x")}
    for player in api.get("/api/players") or []:
        if (player.get("user_email") or "").lower() in emails:
            api.delete(f"/api/players/{player['user_id']}")
    names = {g["name"] for g in _google("/groups", "groups", customer="x")}
    for team in api.get("/api/teams") or []:
        if team.get("team_name") in names:
            api.delete(f"/api/teams/{team['team_id']}")


def _google_user_checks(api: OpenAEV, user: dict, team: dict | None) -> list[Check]:
    players = {(p.get("user_email") or "").lower(): p for p in api.get("/api/players") or []}
    tags = _tag_names(api)
    player = players.get(user["primaryEmail"].lower())
    names = {tags.get(t) for t in (player or {}).get("user_tags") or []}
    wanted = {"source:google-workspace", "status:active"}
    if user["orgUnitPath"] != "/":
        wanted.add("org-unit:" + user["orgUnitPath"].strip("/").replace("/", "-").lower())
    if user.get("isAdmin"):
        wanted.add("role:admin")
    if user.get("isDelegatedAdmin"):
        wanted.add("role:delegated-admin")
    email = user["primaryEmail"]
    checks: list[Check] = [
        (f"user {email} imported with their names",
         bool(player) and (player["user_firstname"], player["user_lastname"])
         == (user["name"]["givenName"], user["name"]["familyName"]), player),
        (f"user {email} tagged {', '.join(sorted(wanted))}",
         wanted <= names, sorted(filter(None, names))),
    ]  # fmt: skip
    if team is not None:
        checks.append(
            (f"user {email} in team {team.get('team_name')}",
             bool(player) and player["user_id"] in (team.get("team_users") or []),
             team.get("team_users"))
        )  # fmt: skip
    return checks


def _google_groups_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    teams = _by(api.get("/api/teams"), "team_name")
    users = {u["primaryEmail"]: u for u in _google("/users", "users", customer="x")}
    players = {(p.get("user_email") or "").lower() for p in api.get("/api/players") or []}
    checks: list[Check] = []
    members_anywhere = set()
    for group in _google("/groups", "groups", customer="x"):
        team = teams.get(group["name"])
        checks.append((f"group {group['email']} imported as a team", bool(team), None))
        for member in _google(f"/groups/{group['email']}/members", "members"):
            members_anywhere.add(member["email"])
            user = users.get(member["email"])
            if member["type"] != "USER":
                checks.append(
                    (f"nested {member['type'].lower()} {member['email']} not imported as a "
                     "user", member["email"].lower() not in players, None)
                )  # fmt: skip
            elif user is None:
                checks.append(
                    (f"outside member {member['email']} not imported",
                     member["email"].lower() not in players, None)
                )  # fmt: skip
            elif user["suspended"]:
                checks.append(
                    (f"suspended user {user['primaryEmail']} not imported",
                     user["primaryEmail"].lower() not in players, None)
                )  # fmt: skip
            else:
                checks += _google_user_checks(api, user, team or {})
    for email in set(users) - members_anywhere:
        checks.append(
            (f"user {email} in no group not imported (group sync)",
             email.lower() not in players, None)
        )  # fmt: skip
    return checks


def _google_all_users_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    players = {(p.get("user_email") or "").lower() for p in api.get("/api/players") or []}
    checks: list[Check] = []
    for user in _google("/users", "users", customer="x"):
        if user["suspended"]:
            checks.append(
                (f"suspended user {user['primaryEmail']} not imported",
                 user["primaryEmail"].lower() not in players, None)
            )  # fmt: skip
        else:
            checks += _google_user_checks(api, user, None)
    return checks


def _google_env(sync_all: bool) -> Callable[[Ofapi], dict[str, str]]:
    return lambda fake: {
        "COLLECTOR_GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON": _google_service_account(fake),
        "COLLECTOR_GOOGLE_WORKSPACE_DELEGATED_ADMIN_EMAIL": "admin@staticfire.test",
        "COLLECTOR_GOOGLE_WORKSPACE_CUSTOMER_ID": "my_customer",
        "COLLECTOR_INCLUDE_SUSPENDED": "false",
        "COLLECTOR_SYNC_ALL_USERS": "true" if sync_all else "false",
        "COLLECTOR_PERIOD": "PT1H",
    }


GOOGLE_WORKSPACE = CatalogCollector(
    recipe="google-workspace",
    collector="google-workspace",
    env=_google_env(False),
    checks=_google_groups_checks,
    calls=["/google-identity/token", f"{GOOGLE_ADMIN}/groups"],
    proxy=True,
    setup=_google_setup,
    test_packages=["pysocks"],
    description="2 Workspace groups: active users (admin, delegated admin), a suspended user, "
    "a nested group and an outside address as members; a user in no group",
)

GOOGLE_WORKSPACE_ALL_USERS = CatalogCollector(
    recipe="google-workspace-all-users",
    collector="google-workspace",
    env=_google_env(True),
    checks=_google_all_users_checks,
    calls=["/google-identity/token", f"{GOOGLE_ADMIN}/users"],
    proxy=True,
    setup=_google_setup,
    test_packages=["pysocks"],
    description="every active Workspace user (sync all users), the suspended one left out",
)


# -- OVHcloud (API v1 through the proxy: eu.api.ovh.com, www.ovh.com) --

OVH = "/ovhcloud/1.0"
OVH_APP_KEY, OVH_APP_SECRET = "staticfireOvhAppKey1", "staticfireOvhAppSecret1"


def _ovh_get(path: str):
    """The fake account, read with an OAuth2 token as any API client would."""
    fake = Ofapi()
    token = fake.http.post(
        "/ovhcloud/auth/oauth2/token",
        data={"grant_type": "client_credentials", "client_id": "check", "client_secret": "x"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return fake.http.get(f"{OVH}{path}", headers=headers).raise_for_status().json()


def _ovh_hosts(addresses: list[str]) -> set[str]:
    """The host addresses of a list of IPs and CIDR blocks (blocks of several left out)."""
    import ipaddress

    hosts = set()
    for raw in addresses:
        network = ipaddress.ip_network(raw, strict=False)
        if network.num_addresses == 1:
            hosts.add(str(network.network_address))
    return hosts


def _ovh_expected() -> tuple[list[dict], list[tuple[str, str]]]:
    """(endpoints the collector must create, (reference, why) of what it must skip)."""
    wanted, skipped = [], []
    for name in _ovh_get("/dedicated/server"):
        server = _ovh_get(f"/dedicated/server/{name}")
        if server["iam"]["state"] != "OK":
            skipped.append((name, f"dedicated server {server['iam']['state'].lower()}"))
            continue
        ips = _ovh_hosts([server["ip"], *_ovh_get(f"/dedicated/server/{name}/ips")])
        windows = server["os"].startswith("win")
        wanted.append(
            {"ref": name, "label": f"dedicated server {name}", "type": "dedicated_server",
             "platform": "Windows" if windows else "Linux", "ips": ips,
             "tags": {f"ovh-environment:{server['iam']['tags']['environment']}"}}
        )  # fmt: skip
    for project in _ovh_get("/cloud/project"):
        for instance in _ovh_get(f"/cloud/project/{project}/instance"):
            if instance["status"] != "ACTIVE":
                skipped.append((instance["id"], f"instance {instance['status'].lower()}"))
                continue
            detail = _ovh_get(f"/cloud/project/{project}/instance/{instance['id']}")
            wanted.append(
                {"ref": instance["id"], "label": f"Public Cloud instance {instance['name']}",
                 "type": "public_cloud_instance",
                 "platform": detail["image"]["type"].title(),
                 "ips": {a["ip"] for a in instance["ipAddresses"]},
                 "tags": {f"ovh-project:{project}"}}
            )  # fmt: skip
    for name in _ovh_get("/vps"):
        image = _ovh_get(f"/vps/{name}/images/current")
        wanted.append(
            {"ref": name, "label": f"VPS {name}", "type": "vps",
             "platform": "Linux" if "linux" in image["name"].lower() else "Unknown",
             "ips": set(_ovh_get(f"/vps/{name}/ips")), "tags": {"ovh-team:infra"}}
        )  # fmt: skip
    for service in _ovh_get("/dedicatedCloud"):
        for dc in _ovh_get(f"/dedicatedCloud/{service}/datacenter"):
            for vm_id in _ovh_get(f"/dedicatedCloud/{service}/datacenter/{dc}/vm"):
                vm = _ovh_get(f"/dedicatedCloud/{service}/datacenter/{dc}/vm/{vm_id}")
                ref = f"{service}/{dc}/{vm_id}"
                if vm["powerState"] == "deleted":
                    skipped.append((ref, "VMware VM deleted"))
                    continue
                wanted.append(
                    {"ref": ref, "label": f"VMware VM {vm['name']}",
                     "type": "hosted_private_cloud_vm",
                     "platform": "Linux" if vm["guestOsFamily"].startswith("linux")
                     else "Windows", "ips": set(),
                     "macs": {_mac(n["macAddress"]) for n in vm["networks"]}, "tags": set()}
                )  # fmt: skip
    return wanted, skipped


def _mac(value: str) -> str:
    """A MAC address as the platform stores it: lower case, no separator."""
    return value.replace(":", "").replace("-", "").lower()


def _ovh_setup(api: OpenAEV, _fake: Ofapi) -> None:
    wanted, skipped = _ovh_expected()
    refs = {w["ref"] for w in wanted} | {ref for ref, _ in skipped}
    for endpoint in api.endpoints() or []:
        if endpoint.get("asset_external_reference") in refs:
            api.delete(f"/api/endpoints/{endpoint['asset_id']}")


def _ovh_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    wanted, skipped = _ovh_expected()
    endpoints = _by(api.endpoints(), "asset_external_reference")
    tags = _tag_names(api)
    checks: list[Check] = []
    for item in wanted:
        found = endpoints.get(item["ref"]) or {}
        names = {tags.get(t) for t in _endpoint_tags(api, found)}
        expected_tags = {"source:ovhcloud", f"ovh-type:{item['type']}", *item["tags"]}
        ips = set(found.get("asset_ips") or [])
        checks += [
            (f"{item['label']} imported as an endpoint", bool(found),
             found and {k: found.get(k) for k in ("asset_name", "endpoint_platform")}),
            (f"{item['label']} platform {item['platform']}",
             found.get("endpoint_platform") == item["platform"], found.get("endpoint_platform")),
            (f"{item['label']} with its host addresses only (no routed block)",
             ips == item["ips"], {"got": sorted(ips), "wanted": sorted(item["ips"])}),
            (f"{item['label']} tagged {', '.join(sorted(expected_tags))}",
             expected_tags <= names, sorted(filter(None, names))),
        ]  # fmt: skip
        if item.get("macs"):
            macs = {_mac(m) for m in found.get("asset_mac_addresses") or []}
            checks.append((f"{item['label']} MAC address", item["macs"] <= macs, sorted(macs)))
    for ref, why in skipped:
        checks.append((f"{why} ({ref}) left out", ref not in endpoints, None))
    return checks


def _ovh_env(oauth2: bool) -> Callable[[Ofapi], dict[str, str]]:
    def env(_fake: Ofapi) -> dict[str, str]:
        auth = (
            {
                "COLLECTOR_OVHCLOUD_CLIENT_ID": "EU.staticfire0000",
                "COLLECTOR_OVHCLOUD_CLIENT_SECRET": "staticfire-ovh-oauth2-secret",
            }  # noqa: E501
            if oauth2
            else {
                "COLLECTOR_OVHCLOUD_APPLICATION_KEY": OVH_APP_KEY,
                "COLLECTOR_OVHCLOUD_APPLICATION_SECRET": OVH_APP_SECRET,
                "COLLECTOR_OVHCLOUD_CONSUMER_KEY": "staticfireOvhConsumerKey000000001",
            }
        )
        return {
            **auth,
            "COLLECTOR_OVHCLOUD_ENDPOINT": "ovh-eu",
            "COLLECTOR_OVHCLOUD_COLLECT_DEDICATED_SERVERS": "true",
            "COLLECTOR_OVHCLOUD_COLLECT_PUBLIC_CLOUD": "true",
            "COLLECTOR_OVHCLOUD_COLLECT_VPS": "true",
            "COLLECTOR_OVHCLOUD_COLLECT_HOSTED_PRIVATE_CLOUD": "true",
            "COLLECTOR_PERIOD": "PT1H",
        }

    return env


OVHCLOUD = CatalogCollector(
    recipe="ovhcloud",
    collector="ovhcloud",
    env=_ovh_env(oauth2=False),
    checks=_ovh_checks,
    calls=[f"{OVH}/auth/time", f"{OVH}/dedicated/server", f"{OVH}/cloud/project", f"{OVH}/vps"],
    proxy=True,
    setup=_ovh_setup,
    description="signed API calls (application key): dedicated servers (one suspended), Public "
    "Cloud instances (one deleted), a VPS, VMware VMs (one deleted)",
)

OVHCLOUD_OAUTH2 = CatalogCollector(
    recipe="ovhcloud-oauth2",
    collector="ovhcloud",
    env=_ovh_env(oauth2=True),
    checks=_ovh_checks,
    calls=["/ovhcloud/auth/oauth2/token", f"{OVH}/dedicated/server"],
    proxy=True,
    setup=_ovh_setup,
    description="the same account through an OAuth2 service account (client credentials)",
)


# -- MITRE ATT&CK (github.com/mitre/cti through the proxy) --

ATTACK_FILE = "/github/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"


def _attack_bundle() -> list[dict]:
    fake = Ofapi()
    path = "/github/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    headers = {"X-Original-Host": "raw.githubusercontent.com"}
    return fake.http.get(path, headers=headers).raise_for_status().json()["objects"]


def _mitre_id(item: dict) -> str:
    return next(
        r["external_id"]
        for r in item.get("external_references") or []
        if r.get("source_name") == "mitre-attack"
    )


def _attack_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    objects = _attack_bundle()
    tactics = [o for o in objects if o["type"] == "x-mitre-tactic"]
    techniques = [o for o in objects if o["type"] == "attack-pattern"]
    parents = {
        o["source_ref"]: o["target_ref"]
        for o in objects
        if o["type"] == "relationship" and o["relationship_type"] == "subtechnique-of"
    }
    phases = _by(api.get("/api/kill_chain_phases"), "phase_external_id")
    patterns = _by(api.get("/api/attack_patterns"), "attack_pattern_external_id")
    by_stix = {p.get("attack_pattern_stix_id"): p for p in patterns.values()}
    checks: list[Check] = []
    for tactic in tactics:
        found = phases.get(_mitre_id(tactic)) or {}
        checks.append(
            (f"tactic {_mitre_id(tactic)} imported as a kill chain phase (this bundle's)",
             found.get("phase_stix_id") == tactic["id"], found.get("phase_stix_id"))
        )  # fmt: skip
    for technique in techniques:
        external_id = _mitre_id(technique)
        found = patterns.get(external_id) or {}
        if technique.get("revoked"):
            checks.append((f"revoked {external_id} skipped", not found, found or None))
            continue
        phase = technique["kill_chain_phases"][0]["phase_name"]
        phase_ids = {
            p.get("phase_id") for p in phases.values() if p.get("phase_shortname") == phase
        }
        checks += [
            (f"technique {external_id} imported (this bundle's)",
             found.get("attack_pattern_stix_id") == technique["id"],
             found.get("attack_pattern_stix_id")),
            (f"technique {external_id} in its tactic {phase}",
             bool(phase_ids & set(found.get("attack_pattern_kill_chain_phases") or [])),
             found.get("attack_pattern_kill_chain_phases")),
        ]  # fmt: skip
        if technique["id"] in parents:
            parent = by_stix.get(parents[technique["id"]]) or {}
            linked = found.get("attack_pattern_parent") == parent.get("attack_pattern_id")
            checks.append(
                (f"sub-technique {external_id} linked to its parent",
                 bool(parent) and linked, found.get("attack_pattern_parent"))
            )  # fmt: skip
    return checks


MITRE_ATTACK = CatalogCollector(
    recipe="mitre-attack",
    collector="mitre-attack",
    env=lambda fake: {"COLLECTOR_PERIOD": "P7D", "COLLECTOR_BATCH_SIZE": "100"},
    checks=_attack_checks,
    calls=[ATTACK_FILE],
    proxy=True,
    description="the Enterprise ATT&CK bundle of github.com/mitre/cti: 5 tactics, techniques "
    "and sub-techniques, a revoked technique",
)


# -- Atomic Red Team (raw.githubusercontent.com/redcanaryco/atomic-red-team) --

ART_INDEX = "/github/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"
# The collector skips these on purpose (already in the OpenAEV repository, destructive)
ART_SKIPPED = {
    "aa6cb8c4-b582-4f8e-b677-37733914abda": "copied to the OpenAEV payloads repository",
    "f3aa95fe-4f10-4485-ad26-abf22a764c52": "forbidden (destructive)",
}
ART_EXECUTORS = {"powershell": "psh", "command_prompt": "cmd", "bash": "bash", "sh": "sh"}
ART_PLATFORMS = {"windows": "Windows", "linux": "Linux", "macos": "MacOS"}


def _art_tests() -> list[tuple[str, dict]]:
    import yaml

    fake = Ofapi()
    headers = {"X-Original-Host": "raw.githubusercontent.com"}
    text = fake.http.get(ART_INDEX, headers=headers).raise_for_status().text
    return [
        (technique, test)
        for techniques in yaml.safe_load(text).values()
        for technique, entry in techniques.items()
        for test in entry["atomic_tests"]
    ]


def _art_checks(api: OpenAEV, collector_id: str) -> list[Check]:
    tags = _tag_names(api)
    checks: list[Check] = []
    for technique, test in _art_tests():
        guid = test["auto_generated_guid"]
        search = {"page": 0, "size": 50, "textSearch": test["name"]}
        found = (api.post("/api/payloads/search", search) or {}).get("content", [])
        listed = next((i for i in found if i.get("payload_external_id") == guid), None)
        payload = api.get(f"/api/payloads/{listed['payload_id']}") if listed else {}
        label = f"atomic test '{test['name']}' ({technique})"
        if guid in ART_SKIPPED or test["executor"]["name"] == "manual":
            why = ART_SKIPPED.get(guid, "manual, no command")
            mine = payload.get("payload_collector") == collector_id if payload else False
            checks.append((f"{label} not imported: {why}", not mine, payload or None))
            continue
        platforms = sorted({ART_PLATFORMS[p] for p in test["supported_platforms"]})
        names = {tags.get(t) for t in payload.get("payload_tags") or []}
        content = payload.get("command_content") or ""
        arguments = {a["key"] for a in payload.get("payload_arguments") or []}
        wanted_tags = {"source:atomic-red-team", f"technique:{technique.lower()}"}
        checks += [
            (f"{label} imported as a community Command payload",
             payload.get("payload_type") == "Command"
             and payload.get("payload_source") == "COMMUNITY",
             payload and {k: payload.get(k) for k in ("payload_type", "payload_source")}),
            (f"{label} executor {ART_EXECUTORS[test['executor']['name']]}, platforms "
             f"{platforms}",
             payload.get("command_executor") == ART_EXECUTORS[test["executor"]["name"]]
             and sorted(payload.get("payload_platforms") or []) == platforms,
             payload and {k: payload.get(k) for k in ("command_executor", "payload_platforms")}),
            (f"{label} keeps its input arguments",
             set(test.get("input_arguments") or {}) <= arguments, sorted(arguments)),
            (f"{label} command has no PathToAtomicsFolder left",
             bool(content) and "PathToAtomicsFolder" not in content, content[:300]),
            (f"{label} tagged {', '.join(sorted(wanted_tags))}",
             wanted_tags <= names, sorted(filter(None, names))),
        ]  # fmt: skip
        # Every #{...} the payload uses must be one of its arguments, named as a key can be
        texts = [content, payload.get("payload_cleanup_command") or ""] + [
            f"{p.get('get_command')}\n{p.get('check_command')}"
            for p in payload.get("payload_prerequisites") or []
        ]
        used = set(re.findall(r"#\{([^}]*)\}", "\n".join(texts)))
        checks += [
            (f"{label} uses only its own arguments", used <= arguments, sorted(used - arguments)),
            (f"{label} argument names are well formed",
             all(re.fullmatch(r"\w+", key) for key in arguments), sorted(arguments)),
        ]  # fmt: skip
    return checks


ATOMIC_RED_TEAM = CatalogCollector(
    recipe="atomic-red-team",
    collector="atomic-red-team",
    env=lambda fake: {"COLLECTOR_PERIOD": "P7D"},
    checks=_art_checks,
    calls=[ART_INDEX],
    proxy=True,
    description="an index of 6 atomic tests: sh, PowerShell with PathToAtomicsFolder "
    "dependencies, cmd with an ExternalPayloads tool, manual, ignored and forbidden ones",
)


# -- OpenAEV scenarios (releases of github.com/OpenAEV-Platform/scenarios, dry run) --
# The collector runs dry by default: it verifies a release and reports what it would send.
# What it reports is in its log; its GitHub calls in the fake's journal.

SCENARIOS_RUN = "collector-scenarios"
SCENARIOS_TOKEN = "github_pat_11STATICFIRE0fake0token0for0scenarios"


def _scenarios_log() -> str:
    from staticfire import runner

    logs = sorted((runner.RUNS_DIR / SCENARIOS_RUN).glob("*.log"))
    return logs[-1].read_text(errors="replace") if logs else ""


def _scenarios_release(repository: str) -> dict:
    fake = Ofapi()
    headers = {"X-Original-Host": "api.github.com"}
    base = f"/github/repos/{repository}"
    pointer = fake.http.get(
        f"{base}/contents/edge.json",
        params={"ref": "channels"},
        headers={**headers, "Accept": "application/vnd.github.raw+json"},
    ).json()
    release = fake.http.get(f"{base}/releases/tags/{pointer['release']}", headers=headers).json()
    manifest_asset = next(a for a in release["assets"] if a["name"] == "manifest.json")
    manifest = fake.http.get(
        f"{base}/releases/assets/{manifest_asset['id']}",
        headers={**headers, "Accept": "application/octet-stream"},
        follow_redirects=False,
    )
    stored = manifest.headers["location"].split("githubusercontent.com", 1)[1]
    document = fake.http.get(
        "/github" + stored,
        headers={"X-Original-Host": "release-assets.githubusercontent.com"},
    ).json()
    return {"pointer": pointer, "manifest": document}


def _token_checks(repository: str) -> list[Check]:
    fake = Ofapi()

    def collector_calls(path: str) -> list[dict]:
        # Its own requests only: other tests may read the same repository
        return [
            c
            for c in fake.journal(path)
            if c["headers"].get("user-agent") == "openaev-scenarios-collector"
        ]

    api_calls = collector_calls(f"/github/repos/{repository}/")
    stored = collector_calls(f"/github/github-production-release-asset/{repository}/")
    return [
        ("the GitHub token is sent to the API host",
         bool(api_calls) and all("authorization" in c["headers"] for c in api_calls),
         [sorted(c["headers"]) for c in api_calls[:2]]),
        ("the release assets are downloaded from the storage host, without the token",
         bool(stored) and not any("authorization" in c["headers"] for c in stored),
         [sorted(c["headers"]) for c in stored[:2]]),
    ]  # fmt: skip


def _scenarios_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    release = _scenarios_release("OpenAEV-Platform/scenarios")
    manifest, log = release["manifest"], _scenarios_log()
    name = release["pointer"]["release"]
    summary = (
        f"Dry run: release {name} verified, {len(manifest['items'])} scenario(s), "
        f"{len(manifest['payloads'])} payload version(s)"
    )
    checks: list[Check] = [(f"reports '{summary}'", summary in log, log[-1500:])]
    for item in manifest["items"]:
        line = f"Dry run: scenario {item['external_id']} {item['version']}"
        checks.append(
            (f"reports scenario {item['external_id']} {item['version']}", line in log, None)
        )
    checks.append(("reports no error", '"level": "ERROR"' not in log, None))
    return checks + _token_checks("OpenAEV-Platform/scenarios")


def _scenarios_tampered_checks(api: OpenAEV, _collector_id: str) -> list[Check]:
    release = _scenarios_release("OpenAEV-Platform/scenarios-tampered")
    log, name = _scenarios_log(), release["pointer"]["release"]
    archive = release["manifest"]["items"][0]["archive"]["name"]
    return [
        (f"refuses the release whose {archive} is not the one listed",
         "is not used" in log and f"{archive} has another SHA-256" in log, log[-1500:]),
        ("verifies nothing it would send", f"release {name} verified" not in log, None),
    ]  # fmt: skip


def _scenarios_env(repository: str) -> Callable[[Ofapi], dict[str, str]]:
    return lambda fake: {
        "SCENARIOS_REPOSITORY": repository,
        "SCENARIOS_CHANNEL": "edge",
        "SCENARIOS_GITHUB_TOKEN": SCENARIOS_TOKEN,
        "SCENARIOS_DRY_RUN": "true",
        "COLLECTOR_LOG_LEVEL": "info",
        "COLLECTOR_PERIOD": "PT1H",
    }


SCENARIOS = CatalogCollector(
    recipe="scenarios",
    collector="scenarios",
    env=_scenarios_env("OpenAEV-Platform/scenarios"),
    checks=_scenarios_checks,
    calls=[
        "/github/repos/OpenAEV-Platform/scenarios/contents/edge.json",
        "/github/repos/OpenAEV-Platform/scenarios/releases/tags/",
        "/github/github-production-release-asset/OpenAEV-Platform/scenarios/",
    ],
    proxy=True,
    timeout=120,
    description="dry run on the edge channel: a release of 2 scenario archives and a payload "
    "version is verified (pointer, manifest, assets) and reported, the token kept to GitHub's "
    "API host",
)

SCENARIOS_TAMPERED = CatalogCollector(
    recipe="scenarios-tampered",
    collector="scenarios",
    env=_scenarios_env("OpenAEV-Platform/scenarios-tampered"),
    checks=_scenarios_tampered_checks,
    calls=["/github/github-production-release-asset/OpenAEV-Platform/scenarios-tampered/"],
    proxy=True,
    timeout=120,
    description="dry run on a release whose archive changed after its manifest was written: "
    "refused",
)

SPECS: dict[str, CatalogCollector] = {
    spec.recipe: spec
    for spec in [
        MITRE_ATLAS,
        NVD_NIST_CVE,
        OPENAEV_PAYLOADS,
        AWS_RESOURCES,
        MICROSOFT_ENTRA,
        MICROSOFT_INTUNE,
        MICROSOFT_INTUNE_GROUPS,
        MICROSOFT_AZURE,
        MICROSOFT_AZURE_SUBSCRIPTION,
        GOOGLE_WORKSPACE,
        GOOGLE_WORKSPACE_ALL_USERS,
        OVHCLOUD,
        OVHCLOUD_OAUTH2,
        MITRE_ATTACK,
        ATOMIC_RED_TEAM,
        SCENARIOS,
        SCENARIOS_TAMPERED,
    ]
}
