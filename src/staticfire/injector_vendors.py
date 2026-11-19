"""Vendor injectors: how to fire each injector at a fake so its real code runs end to end.

A spec says how to point the injector at ofapi (or which stub replaces its command-line tool),
which contract and content to fire, what the injector must report (status, message, findings)
and which vendor calls it must make. ``recipes.vendor_injector`` runs any spec.

Stubs reproduce a tool's command-line contract and output format (from the injector's own parser),
so the injector's command building and parsing run for real; only the tool's work is canned.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from staticfire.config import STATE_DIR
from staticfire.fakes import Ofapi
from staticfire.vendors import Rule

STUBS_DIR = STATE_DIR / "stubs"


@dataclass
class Context:
    """What a spec can use to build settings and content."""

    fake: Ofapi
    token: str
    stub_dir: Path
    endpoint: dict | None = None

    @property
    def endpoint_ip(self) -> str:
        return (self.endpoint or {}).get("ip") or "192.168.252.2"


@dataclass
class VendorInjector:
    recipe: str
    injector: str  # directory in the injectors repository
    contract: str
    env: Callable[[Context], dict[str, str]]
    content: Callable[[Context], dict]
    rules: Callable[[Context], list[Rule]] = lambda ctx: []
    # Executable name -> script: written to a stub directory put first on PATH
    stubs: dict[str, str] = field(default_factory=dict)
    # Target the endpoint with an agent (its asset id is passed as inject asset)
    target_endpoint: bool = False
    expectations: list[str] = field(default_factory=list)
    status: str = "EXECUTED"
    # Regex the injector's completion message must match
    message: str = ""
    # (finding type, substring of its value) the inject must have produced
    findings: list[tuple[str, str]] = field(default_factory=list)
    # (method, path prefix) the injector must have called on the fake
    calls: list[tuple[str, str]] = field(default_factory=list)
    description: str = ""


def write_stubs(spec: VendorInjector) -> Path:
    directory = STUBS_DIR / spec.recipe
    directory.mkdir(parents=True, exist_ok=True)
    for name, script in spec.stubs.items():
        path = directory / name
        path.write_text(script)
        path.chmod(0o755)
    return directory


def gws_service_account(ctx: Context) -> str:
    """A service account JSON whose token endpoint is the fake (google-auth signs a real JWT)."""
    import json

    key = STATE_DIR / "tls" / "gws-key.pem"
    if not key.exists():
        key.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(key),
            ],
            check=True,
            capture_output=True,
        )
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "staticfire",
            "private_key_id": "staticfire",
            "private_key": key.read_text(),
            "client_email": "staticfire@staticfire.iam.gserviceaccount.com",
            "client_id": "1",
            "token_uri": ctx.fake.http_url("google-oauth2/token"),
        }
    )


# -- HTTP API injectors --

CENSYS = VendorInjector(
    recipe="censys",
    injector="censys",
    contract="9c5d4e7f-3d44-4f51-8e60-4b5c6d7e8f90",
    env=lambda ctx: {
        "CENSYS_BASE_URL": ctx.fake.http_url("censys"),
        "CENSYS_API_ID": "staticfire-id",
        "CENSYS_API_SECRET": "staticfire-fake-secret",
    },
    content=lambda ctx: {"query": "services.port=443"},
    message=r"Found \d+ hosts",
    findings=[("ipv4", ".")],
    calls=[("GET", "/censys/api/v2/hosts/search")],
    description="host search: hosts and ports become findings",
)

SHODAN_SEARCH = "/shodan/shodan/host/search"

SHODAN = VendorInjector(
    recipe="shodan",
    injector="shodan",
    contract="c7640b4c-8a12-458a-b761-6a1287501a58",
    env=lambda ctx: {
        # The client joins paths with urljoin: the base must end with a slash
        "SHODAN_BASE_URL": ctx.fake.http_url("shodan") + "/",
        "SHODAN_API_KEY": "staticfire-fake-key",
        "SHODAN_API_RETRY": "2",
        "SHODAN_API_BACKOFF": "PT1S",
    },
    content=lambda ctx: {
        "target_selector": "manual",
        "target_property_selector": "automatic",
        "auto_create_assets": False,
        "custom_query": f"hostname:{ctx.token}.staticfire.test",
        "expectations": [],
    },
    rules=lambda ctx: [
        Rule(
            SHODAN_SEARCH,
            {
                "total": 1,
                "matches": [
                    {
                        "ip_str": "198.51.100.7",
                        "hostnames": [f"{ctx.token}.staticfire.test"],
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "os": "Linux",
                        "vulns": {"CVE-2021-44228": {"cvss": 10.0}},
                    }
                ],
            },
            method="GET",
        )
    ],
    findings=[("cve", "CVE-2021-44228"), ("ipv4", "198.51.100.7")],
    calls=[("GET", SHODAN_SEARCH), ("GET", "/shodan/api-info")],
    description="custom query: a match with a CVE becomes CVE, IP and port findings",
)

SLACK = VendorInjector(
    recipe="slack",
    injector="slack",
    contract="b3f6a1d2-8c47-4e2a-9f1b-2a7c5d0e9f10",
    env=lambda ctx: {
        "SLACK_BASE_URL": ctx.fake.http_url("slack/api"),
        "SLACK_BOT_TOKEN": "xoxb-staticfire-fake",
    },
    content=lambda ctx: {
        "channel": "#staticfire",
        "content_type": "text",
        "title": f"staticfire {ctx.token}",
        "message": f"slack probe {ctx.token}",
    },
    message="Slack message sent successfully",
    calls=[("POST", "/slack/api/chat.postMessage")],
    description="post a message to a channel",
)

TEAMS = VendorInjector(
    recipe="teams",
    injector="teams",
    contract="c98e373e-3265-4aee-a2bb-36f7cb81e93e",
    env=lambda ctx: {
        "TEAMS_AUTHORITY_BASE_URL": ctx.fake.http_url("microsoft-identity"),
        "TEAMS_GRAPH_BASE_URL": ctx.fake.http_url("microsoft-graph/v1.0"),
        "TEAMS_TENANT_ID": "00000000-0000-4000-8000-000000000001",
        "TEAMS_CLIENT_ID": "staticfire-client",
        "TEAMS_CLIENT_SECRET": "staticfire-fake-secret",
        "TEAMS_REFRESH_TOKEN": "staticfire-fake-refresh",
    },
    content=lambda ctx: {
        "target_type": "channel",
        "team_id": "staticfire-team",
        "channel_id": "19:staticfire@thread.tacv2",
        "content_type": "text",
        "title": f"staticfire {ctx.token}",
        "message": f"teams probe {ctx.token}",
    },
    message="Teams channel message sent successfully",
    calls=[
        ("POST", "/microsoft-identity/00000000-0000-4000-8000-000000000001/oauth2/v2.0/token"),
        ("POST", "/microsoft-graph/v1.0/teams/staticfire-team/channels/"),
    ],
    description="refresh-token login, then a channel message through Graph",
)

EMAIL_GWS = VendorInjector(
    recipe="email-google-workspace",
    injector="email-google-workspace",
    contract="c4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f",
    env=lambda ctx: {
        "GWS_SERVICE_ACCOUNT_JSON": gws_service_account(ctx),
        "GWS_GMAIL_BASE_URL": ctx.fake.http_url("gmail/v1"),
    },
    content=lambda ctx: {
        "from": "sender@staticfire.test",
        "to": f"{ctx.token}@staticfire.test",
        "subject": f"[staticfire {ctx.token}] gmail",
        "body_format": "text",
        "body": f"gmail probe {ctx.token}",
    },
    message="Email sent through Gmail",
    calls=[("POST", "/google-oauth2/token"), ("POST", "/gmail/v1/users/me/messages/send")],
    description="service-account JWT login, then a Gmail send",
)

M365_TENANT = "00000000-0000-4000-8000-000000000002"

# MSAL refuses an authority that is not Microsoft's unless instance discovery is off; the
# injector does not expose it, so the test turns it off when the interpreter starts
MSAL_NO_DISCOVERY = """
try:
    import msal

    _init = msal.ConfidentialClientApplication.__init__

    def _no_discovery(self, *args, **kwargs):
        kwargs.setdefault("instance_discovery", False)
        _init(self, *args, **kwargs)

    msal.ConfidentialClientApplication.__init__ = _no_discovery
except Exception:
    pass
"""

EMAIL_M365 = VendorInjector(
    recipe="email-m365",
    injector="email-m365",
    contract="a1c2e3f4-5b6d-4e7f-8a9b-0c1d2e3f4a5b",
    env=lambda ctx: {
        # MSAL requires an https authority: the fake's TLS port, trusted through the CA bundle
        "M365_AUTHORITY_BASE_URL": ctx.fake.https_url("microsoft-identity"),
        "M365_GRAPH_BASE_URL": ctx.fake.http_url("microsoft-graph/v1.0"),
        "M365_TENANT_ID": M365_TENANT,
        "M365_CLIENT_ID": "staticfire-client",
        "M365_CLIENT_SECRET": "staticfire-fake-secret",
        "REQUESTS_CA_BUNDLE": str(ctx.fake.cert),
        "PYTHONPATH": str(ctx.stub_dir),
    },
    content=lambda ctx: {
        "from": "sender@staticfire.test",
        "to": f"{ctx.token}@staticfire.test",
        "subject": f"[staticfire {ctx.token}] m365",
        "body_format": "text",
        "body": f"m365 probe {ctx.token}",
    },
    stubs={"sitecustomize.py": MSAL_NO_DISCOVERY},
    message="Email accepted by Microsoft Graph",
    calls=[
        ("POST", f"/microsoft-identity/{M365_TENANT}/oauth2/v2.0/token"),
        ("POST", "/microsoft-graph/v1.0/users/sender%40staticfire.test/sendMail"),
    ],
    description="client-credentials login (MSAL, test-side discovery patch), then sendMail",
)

# -- command-line tool injectors (stubbed tools) --

NMAP_STUB = r"""#!/bin/sh
# staticfire stub: nmap -Pn -sT -oX - <targets...>, prints an XML report with ports 22 and 80
# open on every target, the shape nmap_output_parser reads
target=""
for arg in "$@"; do target="$arg"; done
printf '<?xml version="1.0"?><nmaprun scanner="nmap">'
for t in "$@"; do
  case "$t" in -*) continue ;; esac
  printf '<host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports>' "$t"
  printf '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
  printf '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
  printf '</ports></host>'
done
printf '</nmaprun>\n'
"""

NMAP = VendorInjector(
    recipe="nmap",
    injector="nmap",
    contract="93d27459-68d0-43b1-ad65-eacc3cfa5cf7",
    env=lambda ctx: {},
    content=lambda ctx: {"target_selector": "assets", "target_property_selector": "automatic"},
    stubs={"nmap": NMAP_STUB},
    target_endpoint=True,
    expectations=["DETECTION", "PREVENTION"],
    message=r"Targets successfully scanned",
    findings=[("portscan", "22")],
    description="TCP connect scan of the agent endpoint (stubbed nmap): open ports become findings",
)

NETEXEC_STUB = r"""#!/bin/sh
# staticfire stub: netexec --version, or netexec smb <targets> ... --shares
if [ "$1" = "--version" ]; then echo "1.4.0"; exit 0; fi
host="$2"
echo "SMB  $host  445  STATICFIRE  [*] Linux Samba (name:STATICFIRE) (signing:False)"
echo "SMB  $host  445  STATICFIRE  [+] \\alice:secret"
echo "SMB  $host  445  STATICFIRE  [*] Enumerated shares"
echo "SMB  $host  445  STATICFIRE  Share     Permissions  Remark"
echo "SMB  $host  445  STATICFIRE  -----     -----------  ------"
echo "SMB  $host  445  STATICFIRE  public    READ,WRITE   Public share"
echo "SMB  $host  445  STATICFIRE  IPC\$      READ         IPC"
"""

NETEXEC = VendorInjector(
    recipe="netexec",
    injector="netexec",
    contract="netexec_smb_opt_shares",
    env=lambda ctx: {},
    content=lambda ctx: {
        "target_selector": "manual",
        "targets": ctx.endpoint_ip,
        "username": "alice",
        "password": "secret",
    },
    stubs={"netexec": NETEXEC_STUB},
    message=r"NetExec succeeded",
    findings=[("share", "public")],
    description="SMB share enumeration (stubbed netexec): shares become findings",
)

# prowler runs with an exact environment and no PATH: /bin/sh builtins only
PROWLER_STUB = r"""#!/bin/sh
# staticfire stub: prowler aws ... --output-directory <dir> --output-filename findings -M json-ocsf
dir=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--output-directory" ]; then dir="$arg"; fi
  prev="$arg"
done
printf '%s\n' '-> Using the AWS credentials below:'
printf '%s\n' '  · AWS Account: 123456789012'
printf '%s\n' '  · Caller Identity ARN: arn:aws:iam::123456789012:user/prowler'
printf '%s' '[{"finding_info":{"uid":"prowler-aws-iam_root_mfa_enabled","title":"Ensure MFA is enabled for the root account","desc":"Root has no MFA","remediation":{"desc":"Enable MFA","references":["https://docs.aws.amazon.com/IAM/"]}},"status":"New","status_code":"FAIL","severity":"High","resources":[{"uid":"arn:aws:iam::123456789012:root","name":"root"}],"cloud":{"provider":"aws","region":"us-east-1","account":{"uid":"123456789012"}}}]' > "$dir/findings.ocsf.json"
"""

PROWLER = VendorInjector(
    recipe="prowler",
    injector="prowler",
    contract="a0464aa7-9451-54ea-bc00-3e89019a315a",
    env=lambda ctx: {"PROWLER_EXECUTABLE_PATH": str(ctx.stub_dir / "prowler")},
    content=lambda ctx: {
        "aws_access_key_id": "AKIASTATICFIREFAKE",
        "aws_secret_access_key": "staticfire-fake-secret",
        "aws_account_id": "123456789012",
        "aws_region": "us-east-1",
    },
    stubs={"prowler": PROWLER_STUB},
    findings=[("vulnerability", "MFA")],
    description="AWS scan (stubbed prowler): a failed check becomes a vulnerability finding",
)

STRATUS_STUB = r"""#!/bin/sh
# staticfire stub: stratus detonate <technique> --cleanup
echo "2026/11/19 10:00:00 Checking your authentication against AWS"
echo "2026/11/19 10:00:01 Warming up $2..."
echo "2026/11/19 10:00:02 Detonating $2"
"""

STRATUS = VendorInjector(
    recipe="stratus",
    injector="stratus",
    contract="5ca462c2-9f39-47e2-9a23-94f39dd725e4",
    env=lambda ctx: {},
    content=lambda ctx: {
        "credential_source": "manual",
        "technique_id": "aws.discovery.ec2-enumerate-from-instance",
        "aws_access_key_id": "AKIASTATICFIREFAKE",
        "aws_secret_access_key": "staticfire-fake-secret",
        "aws_region": "us-east-1",
    },
    stubs={"stratus": STRATUS_STUB},
    message=r"Detonated aws\.discovery\.ec2-enumerate-from-instance",
    description="detonate a technique (stubbed stratus)",
)

AWS_STUB = r"""#!/bin/sh
# staticfire stub: aws s3 ls
if [ "$1 $2" = "s3 ls" ]; then
  echo "2025-07-29 06:15:56 staticfire-bucket-1"
  echo "2025-07-29 06:16:10 staticfire-bucket-2"
  exit 0
fi
echo "staticfire stub: unsupported aws command $*" >&2
exit 2
"""

AWS = VendorInjector(
    recipe="aws",
    injector="aws",
    contract="a7b8c9d0-e1f2-3456-abcd-567890123456",
    env=lambda ctx: {},
    content=lambda ctx: {
        "aws_access_key_id": "AKIASTATICFIREFAKE",
        "aws_secret_access_key": "staticfire-fake-secret",
        "aws_region": "us-east-1",
    },
    stubs={"aws": AWS_STUB},
    message=r"Found 2 S3 buckets",
    findings=[("text", "staticfire-bucket-1")],
    description="list S3 buckets (stubbed aws CLI): bucket names become findings",
)

SPECS: dict[str, VendorInjector] = {
    spec.recipe: spec
    for spec in [
        CENSYS,
        SHODAN,
        SLACK,
        TEAMS,
        EMAIL_GWS,
        EMAIL_M365,
        NMAP,
        NETEXEC,
        PROWLER,
        STRATUS,
        AWS,
    ]
}
