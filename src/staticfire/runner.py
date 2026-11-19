"""Install and run an injector or collector from its checkout, pointed at the profile's platform.

Each component gets its own virtualenv under the staticfire state directory (the checkout is
installed in editable mode, so local changes are picked up on restart and nothing is written
into the repository). Processes run detached; their pid, log and settings live in
``<state>/runs/<run name>/`` so they can be inspected or stopped from another invocation.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
import tomllib
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from staticfire.config import STATE_DIR, Profile

# Fixed namespace: the same component always registers under the same id, so reruns reuse the
# platform-side registration instead of piling up ghost injectors/collectors.
ID_NAMESPACE = uuid.UUID("5f7a1c2e-9b3d-4e8f-a6c1-2d4b6e8f0a1c")
RUNS_DIR = STATE_DIR / "runs"
VENVS_DIR = STATE_DIR / "venvs"
KINDS = ("injector", "collector")
INSTALLED_MARKER = ".staticfire-installed"


class RunnerError(RuntimeError):
    pass


@dataclass
class Component:
    kind: str
    name: str
    path: str
    module: str

    @property
    def component_id(self) -> str:
        return str(uuid.uuid5(ID_NAMESPACE, f"staticfire:{self.kind}:{self.name}"))

    @property
    def venv(self) -> Path:
        return VENVS_DIR / f"{self.kind}-{self.name}"

    @property
    def python(self) -> Path:
        return self.venv / "bin" / "python"

    @property
    def installed(self) -> bool:
        """Set by a complete install only: a failed one leaves a virtualenv without it."""
        return (self.venv / INSTALLED_MARKER).exists()


def detect(path: str | Path, kind: str | None = None) -> Component:
    """Recognise an injector/collector checkout and the module its Docker image runs."""
    root = Path(path).expanduser().resolve()
    if not (root / "pyproject.toml").exists():
        raise RunnerError(f"{root} has no pyproject.toml")
    if kind is None:
        parent = root.parent.name.lower()
        kind = (
            "collector" if "collector" in parent else "injector" if "injector" in parent else None
        )
    if kind not in KINDS:
        raise RunnerError(f"Cannot tell if {root} is an injector or a collector, pass the kind")
    return Component(kind=kind, name=root.name, path=str(root), module=_module(root))


def _module(root: Path) -> str:
    dockerfile = root / "Dockerfile"
    if dockerfile.exists():
        for line in reversed(dockerfile.read_text().splitlines()):
            if line.startswith(("CMD", "ENTRYPOINT")) and (
                m := re.search(r'"-m",\s*"([^"]+)"', line)
            ):
                return m.group(1)
    scripts = tomllib.loads((root / "pyproject.toml").read_text()).get("project", {}).get("scripts")
    if scripts:
        target = next(iter(scripts.values()))
        return target.split(":", 1)[0]
    raise RunnerError(f"No entry module found in {root} (Dockerfile CMD or project.scripts)")


def install(component: Component, pyoaev: str | None = None, fresh: bool = False) -> str:
    """Create/refresh the component virtualenv; returns the installer output."""
    root = Path(component.path)
    python = _required_python(root)
    if component.python.exists() and _venv_python(component) < python:
        fresh = True  # the component now requires a newer Python than its virtualenv has
    if fresh and component.venv.exists():
        subprocess.run(["rm", "-rf", str(component.venv)], check=True)
    if not component.python.exists():
        _run(["uv", "venv", "--python", ".".join(map(str, python)), str(component.venv)])
    requirements = ["-e", str(root)]
    # Injectors depend on the shared injector_common package through a relative path
    if (
        "injector_common" in (root / "pyproject.toml").read_text()
        and (common := root.parent / "injector_common").exists()
    ):
        requirements += ["-e", str(common)]
    output = _run(["uv", "pip", "install", "--python", str(component.python), *requirements])
    if pyoaev:
        # Test the component against a local pyoaev checkout instead of the pinned release
        output += _run(["uv", "pip", "install", "--python", str(component.python), "-e", pyoaev])
    elif not _importable(component, "pyoaev"):
        # Injectors declare `pyoaev (==X); extra != 'dev'` so their dev extra can swap in a local
        # checkout; uv evaluates that marker to false without extras and skips pyoaev entirely
        output += _run(
            ["uv", "pip", "install", "--python", str(component.python), _pyoaev_pin(root)]
        )
    (component.venv / INSTALLED_MARKER).write_text(component.path + "\n")
    return output


def _required_python(root: Path) -> tuple[int, int]:
    """Lowest Python the component accepts (requires-python), at least 3.11."""
    project = tomllib.loads((root / "pyproject.toml").read_text()).get("project", {})
    m = re.search(r">=\s*3\.(\d+)", project.get("requires-python", ""))
    return (3, max(int(m.group(1)), 11) if m else 12)


def _venv_python(component: Component) -> tuple[int, int]:
    out = subprocess.run(
        [str(component.python), "-c", "import sys; print(*sys.version_info[:2])"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    return (int(out[0]), int(out[1])) if len(out) == 2 else (0, 0)


def _importable(component: Component, module: str) -> bool:
    result = subprocess.run(
        [str(component.python), "-c", f"import {module}"], capture_output=True, check=False
    )
    return result.returncode == 0


def _pyoaev_pin(root: Path) -> str:
    dependencies = tomllib.loads((root / "pyproject.toml").read_text())
    for requirement in dependencies.get("project", {}).get("dependencies", []):
        if m := re.match(r"\s*pyoaev\s*\(?\s*([=<>!~][^);]*)", requirement):
            return "pyoaev" + m.group(1).replace(" ", "")
    return "pyoaev"


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError(f"{' '.join(argv[:3])} failed:\n{result.stderr[-4000:]}")
    return result.stdout + result.stderr


def base_env(component: Component, profile: Profile, log_level: str = "info") -> dict[str, str]:
    prefix = component.kind.upper()
    env = {
        "OPENAEV_URL": profile.openaev_url,
        "OPENAEV_TOKEN": profile.openaev_token,
        f"{prefix}_ID": component.component_id,
        f"{prefix}_LOG_LEVEL": log_level,
    }
    return env


@dataclass
class Run:
    run_name: str
    kind: str
    name: str
    component_id: str
    pid: int
    log: str
    started_at: float
    module: str
    path: str
    env_keys: list[str]

    @property
    def alive(self) -> bool:
        try:
            # Reap it if this process started it: an exited child stays a zombie until then
            if os.waitpid(self.pid, os.WNOHANG)[0] == self.pid:
                return False
        except ChildProcessError:
            pass
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def summary(self) -> dict:
        data = asdict(self)
        data["alive"] = self.alive
        return data


def _run_dir(run_name: str) -> Path:
    return RUNS_DIR / run_name


def start(
    component: Component,
    profile: Profile,
    extra_env: dict[str, str] | None = None,
    run_name: str | None = None,
    log_level: str = "info",
) -> Run:
    if not component.installed:
        raise RunnerError(f"{component.name} is not installed yet, run install first")
    env = {**base_env(component, profile, log_level), **(extra_env or {})}
    return spawn(
        run_name or f"{component.kind}-{component.name}",
        [str(component.python), "-u", "-m", component.module],
        cwd=component.path,
        env=env,
        kind=component.kind,
        name=component.name,
        component_id=component.component_id,
        module=component.module,
    )


def spawn(
    run_name: str,
    argv: list[str],
    cwd: str,
    env: dict[str, str],
    kind: str,
    name: str,
    component_id: str = "",
    module: str = "",
) -> Run:
    """Start a detached process group logging to the run directory."""
    if (existing := get_run(run_name)) and existing.alive:
        raise RunnerError(f"{run_name} is already running (pid {existing.pid}), stop it first")
    run_dir = _run_dir(run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / f"{time.strftime('%Y%m%d-%H%M%S')}.log"
    full_env = {**os.environ, **env}
    full_env.pop("VIRTUAL_ENV", None)
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=full_env,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    run = Run(
        run_name=run_name,
        kind=kind,
        name=name,
        component_id=component_id,
        pid=process.pid,
        log=str(log_path),
        started_at=time.time(),
        module=module,
        path=cwd,
        env_keys=sorted(env),
    )
    (run_dir / "run.json").write_text(json.dumps(asdict(run), indent=2))
    return run


def get_run(run_name: str) -> Run | None:
    meta = _run_dir(run_name) / "run.json"
    if not meta.exists():
        return None
    return Run(**json.loads(meta.read_text()))


def list_runs() -> list[Run]:
    if not RUNS_DIR.exists():
        return []
    return [run for d in sorted(RUNS_DIR.iterdir()) if (run := get_run(d.name))]


def stop(run_name: str, timeout: float = 10.0) -> bool:
    """SIGTERM the run's process group, SIGKILL it if it does not exit in time."""
    run = get_run(run_name)
    if not run or not run.alive:
        return False
    _signal_group(run.pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while run.alive and time.monotonic() < deadline:
        time.sleep(0.2)
    if run.alive:
        _signal_group(run.pid, signal.SIGKILL)
    return True


def _signal_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        # The group is gone, or only holds zombies (macOS answers EPERM for those)
        pass


def tail(run_name: str, lines: int = 60, grep: str | None = None) -> str:
    run = get_run(run_name)
    if not run:
        raise RunnerError(f"Unknown run {run_name}")
    content = Path(run.log).read_text(errors="replace").splitlines()
    if grep:
        pattern = re.compile(grep, re.IGNORECASE)
        content = [line for line in content if pattern.search(line)]
    return "\n".join(content[-lines:])
