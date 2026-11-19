"""Profiles: where the OpenAEV platform under test and its mail catcher live.

A profile is a small JSON file in ``~/.config/staticfire/profiles/<name>.json`` (mode 600, it
holds the admin token). Environment variables override the stored values, so a one-off run can
point anywhere without touching the files.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("STATICFIRE_CONFIG_DIR", Path.home() / ".config" / "staticfire"))
STATE_DIR = Path(
    os.environ.get("STATICFIRE_STATE_DIR", Path.home() / ".local" / "state" / "staticfire")
)
PROFILES_DIR = CONFIG_DIR / "profiles"
CURRENT_FILE = CONFIG_DIR / "current"

ENV_OVERRIDES = {
    "openaev_url": "STATICFIRE_OPENAEV_URL",
    "openaev_token": "STATICFIRE_OPENAEV_TOKEN",
    "mailpit_url": "STATICFIRE_MAILPIT_URL",
    "smtp_host": "STATICFIRE_SMTP_HOST",
    "smtp_port": "STATICFIRE_SMTP_PORT",
}


class ConfigError(RuntimeError):
    pass


@dataclass
class Profile:
    name: str
    openaev_url: str
    openaev_token: str
    # Mail catcher (mailpit) HTTP API, used to check what email injectors sent
    mailpit_url: str | None = None
    # SMTP server as reachable from where injectors run (the laptop), for email injects
    smtp_host: str | None = None
    smtp_port: int = 1025
    # Where the platform runs, used to reach its .env, logs and agent
    multipass_vm: str | None = None
    ssh_target: str | None = None
    deploy_dir: str = "/opt/xtm"
    extra: dict = field(default_factory=dict)

    def public(self) -> dict:
        """The profile without its secret, safe to print or hand to a model."""
        data = asdict(self)
        data["openaev_token"] = "***" if self.openaev_token else ""
        return data

    def remote_command(self, command: str) -> list[str]:
        """argv running ``command`` on the platform host, through multipass or ssh."""
        if self.multipass_vm:
            return ["multipass", "exec", self.multipass_vm, "--", "bash", "-lc", command]
        if self.ssh_target:
            return ["ssh", "-o", "BatchMode=yes", self.ssh_target, command]
        raise ConfigError(f"Profile {self.name} has no multipass_vm or ssh_target")


def _profile_path(name: str) -> Path:
    return PROFILES_DIR / f"{name}.json"


def list_profiles() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))


def current_profile_name() -> str | None:
    if name := os.environ.get("STATICFIRE_PROFILE"):
        return name
    if CURRENT_FILE.exists():
        return CURRENT_FILE.read_text().strip() or None
    profiles = list_profiles()
    return profiles[0] if len(profiles) == 1 else None


def save_profile(profile: Profile, make_current: bool = True) -> Path:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    path = _profile_path(profile.name)
    path.write_text(json.dumps(asdict(profile), indent=2) + "\n")
    path.chmod(0o600)
    if make_current:
        CURRENT_FILE.write_text(profile.name + "\n")
    return path


def load_profile(name: str | None = None) -> Profile:
    name = name or current_profile_name()
    data: dict = {}
    if name:
        path = _profile_path(name)
        if path.exists():
            data = json.loads(path.read_text())
        elif not os.environ.get(ENV_OVERRIDES["openaev_url"]):
            raise ConfigError(f"Unknown profile {name!r}, known: {list_profiles()}")
    data.setdefault("name", name or "env")
    for key, env in ENV_OVERRIDES.items():
        if value := os.environ.get(env):
            data[key] = int(value) if key == "smtp_port" else value
    if not data.get("openaev_url") or not data.get("openaev_token"):
        raise ConfigError(
            "No OpenAEV target: create a profile (staticfire profile from-multipass <vm>) "
            "or set STATICFIRE_OPENAEV_URL and STATICFIRE_OPENAEV_TOKEN"
        )
    data["openaev_url"] = data["openaev_url"].rstrip("/")
    return Profile(**data)


def parse_env_file(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def profile_from_liftoff(
    name: str,
    multipass_vm: str | None = None,
    ssh_target: str | None = None,
    deploy_dir: str = "/opt/xtm",
) -> Profile:
    """Build a profile from the .env liftoff wrote on the platform host."""
    stub = Profile(
        name=name,
        openaev_url="",
        openaev_token="",
        multipass_vm=multipass_vm,
        ssh_target=ssh_target,
        deploy_dir=deploy_dir,
    )
    result = subprocess.run(
        stub.remote_command(f"sudo cat {shlex.quote(deploy_dir)}/.env"),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ConfigError(f"Cannot read {deploy_dir}/.env on the host: {result.stderr.strip()}")
    env = parse_env_file(result.stdout)
    host = env.get("OPENAEV_HOST")
    if not host:
        raise ConfigError(f"OPENAEV_HOST missing from {deploy_dir}/.env")
    scheme = env.get("OPENAEV_EXTERNAL_SCHEME", "http")
    port = env.get("OPENAEV_PORT", "8081")
    stub.openaev_url = f"{scheme}://{host}:{port}"
    stub.openaev_token = env["OPENAEV_ADMIN_TOKEN"]
    # liftoff publishes mailpit (service "mailtrap") on 1025/8025 and points OpenAEV at it
    stub.mailpit_url = f"http://{host}:8025"
    stub.smtp_host = host
    stub.smtp_port = 1025
    return stub
