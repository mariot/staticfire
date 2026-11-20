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
HOMEBREW_LIB = "/opt/homebrew/lib"
VENVS_DIR = STATE_DIR / "venvs"
KINDS = ("injector", "collector", "connector")
# Folders of the OpenCTI connectors repository, each holding connectors of one type
CONNECTOR_FAMILIES = {
    "external-import": "EXTERNAL_IMPORT",
    "internal-enrichment": "INTERNAL_ENRICHMENT",
    "internal-import-file": "INTERNAL_IMPORT_FILE",
    "internal-export-file": "INTERNAL_EXPORT_FILE",
    "stream": "STREAM",
}
INSTALLED_MARKER = ".staticfire-installed"


class RunnerError(RuntimeError):
    pass


@dataclass
class Component:
    kind: str
    name: str
    path: str
    module: str
    # Connectors often run a script (python main.py) from their src/ folder instead of a module
    script: str = ""
    workdir: str = ""
    connector_type: str = ""
    # Or a console script of its pyproject, run from the venv
    entry: str = ""

    @property
    def argv_tail(self) -> list[str]:
        if self.entry:
            return [str(self.venv / "bin" / self.entry)]
        return [self.script] if self.script else ["-m", self.module]

    @property
    def cwd(self) -> str:
        return self.workdir or self.path

    @property
    def component_id(self) -> str:
        stable = uuid.uuid5(ID_NAMESPACE, f"staticfire:{self.kind}:{self.name}")
        if self.kind == "connector":
            # connectors are documented (and some check) to take a UUIDv4: same id, v4 bits
            return str(uuid.UUID(int=stable.int, version=4))
        return str(stable)

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
    family = CONNECTOR_FAMILIES.get(root.parent.name)
    if kind == "connector" or (kind is None and family):
        return _connector(root, family or "")
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


def _connector(root: Path, connector_type: str) -> Component:
    """An OpenCTI connector: its Docker image runs a script from src/ or ``python -m src``."""
    src = root / "src"
    entrypoint = root / "entrypoint.sh"
    dockerfile = root / "Dockerfile"
    script, module, entry, workdir = "", "", "", str(src if src.is_dir() else root)
    if entrypoint.exists() and (
        m := re.findall(r"python3?\s+(?:-m\s+)?(\S+)", entrypoint.read_text())
    ):
        target = m[-1]
        if re.search(r"python3?\s+-m\s+" + re.escape(target), entrypoint.read_text()):
            module = target
            # "python -m src" runs from the connector root, where src/ is a package
            workdir = str(root) if module.split(".")[0] == "src" else workdir
        else:
            script = target
    elif dockerfile.exists():
        for line in reversed(dockerfile.read_text().splitlines()):
            if not line.startswith(("CMD", "ENTRYPOINT")):
                continue
            if m := re.search(r'"-m",\s*"([^"]+)"', line):
                module = m.group(1)
                # "python -m src" runs from the connector root, where src/ is a package
                workdir = str(root) if module.split(".")[0] == "src" else workdir
                break
            if m := re.search(r'"python3?",\s*"([^"]+\.py)"', line):
                script = m.group(1)
                if script.startswith("/opt/"):
                    # the image copies src/ (or the connector) to /opt: run the checkout's file
                    script = Path(script).name
                break
            if m := re.search(r'\[\s*"([\w.-]+)"', line):
                # a console script installed from the connector's pyproject
                target = _console_script(root, m.group(1))
                if target.split(":")[0].endswith(".__main__"):
                    module = target.split(":")[0].removesuffix(".__main__")
                elif target:
                    entry = m.group(1)
                workdir = str(root / "src") if (root / "src").is_dir() else str(root)
                break
    if script.startswith("/"):
        # an absolute path in the image (/opt/<...>/src/main.py): the same file in the checkout
        parts = Path(script).parts[1:]
        script = next(
            (
                str(Path(*parts[i:]))
                for i in range(len(parts))
                if (root / Path(*parts[i:])).exists()
            ),
            script,
        )
        workdir = str(root)
    if script and not (Path(workdir) / script).exists() and (root / script).exists():
        workdir = str(root)
    if not (script or module or entry):
        raise RunnerError(f"No entry point found in {root} (entrypoint.sh or Dockerfile CMD)")
    return Component(
        kind="connector",
        name=root.name,
        path=str(root),
        module=module,
        script=script,
        workdir=workdir,
        connector_type=connector_type,
        entry=entry,
    )


def _installable(root: Path) -> bool:
    pyproject = root / "pyproject.toml"
    return pyproject.exists() and "project" in tomllib.loads(pyproject.read_text())


def _console_script(root: Path, name: str) -> str:
    """The "module:function" of a console script declared in the pyproject, or ""."""
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return ""
    scripts = tomllib.loads(pyproject.read_text()).get("project", {}).get("scripts", {})
    return scripts.get(name, "")


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


def install(
    component: Component,
    pyoaev: str | None = None,
    fresh: bool = False,
    python_version: str | None = None,
) -> str:
    """Create/refresh the component virtualenv; returns the installer output.

    python_version (e.g. "3.13") forces the virtualenv's Python instead of the lowest the
    component accepts.
    """
    root = Path(component.path)
    if python_version:
        python = tuple(int(part) for part in python_version.split(".")[:2])
        fresh = fresh or _venv_python(component) != python
    else:
        python = _required_python(root)
    if component.python.exists() and _venv_python(component) < python:
        fresh = True  # the component now requires a newer Python than its virtualenv has
    if fresh and component.venv.exists():
        subprocess.run(["rm", "-rf", str(component.venv)], check=True)
    if not component.python.exists():
        _run(["uv", "venv", "--python", ".".join(map(str, python)), str(component.venv)])
    if component.kind == "connector":
        requirements = _connector_requirements(root)
        output = _run(["uv", "pip", "install", "--python", str(component.python), *requirements])
        if _installable(root) and str(root) not in requirements:
            # its dependencies are installed: the connector itself, without them
            output += _run(
                [
                    "uv", "pip", "install", "--python", str(component.python),
                    "--no-deps", "-e", str(root),
                ]
            )  # fmt: skip
        (component.venv / INSTALLED_MARKER).write_text(component.path + "\n")
        return output
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
    """Lowest Python the component accepts (requires-python), never below 3.12.

    pyoaev declares >=3.11 but imports typing.override (3.12+): a 3.11 virtualenv installs
    fine and then fails at the first import.
    """
    if not (root / "pyproject.toml").exists():
        return (3, 12)
    project = tomllib.loads((root / "pyproject.toml").read_text()).get("project", {})
    m = re.search(r">=\s*3\.(\d+)", project.get("requires-python", ""))
    return (3, max(int(m.group(1)), 12) if m else 12)


def _venv_python(component: Component) -> tuple[int, int]:
    if not component.python.exists():
        return (0, 0)
    out = subprocess.run(
        [str(component.python), "-c", "import sys; print(*sys.version_info[:2])"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    return (int(out[0]), int(out[1])) if len(out) == 2 else (0, 0)


def _connector_requirements(root: Path) -> list[str]:
    """What the connector's Dockerfile installs: src/requirements.txt or the project itself.

    The connectors SDK is taken from the same checkout (its connectors-sdk folder) rather than
    from GitHub's master, so a connector and the SDK it is tested with come from one tree.
    """
    requirements = []
    sdk = next(
        (p / "connectors-sdk" for p in root.parents if (p / "connectors-sdk").is_dir()), None
    )
    for candidate in (root / "src" / "requirements.txt", root / "requirements.txt"):
        if not candidate.exists():
            continue
        lines = candidate.read_text().splitlines()
        if sdk and any(line.strip().startswith("connectors-sdk") for line in lines):
            local = [line for line in lines if not line.strip().startswith("connectors-sdk")]
            rewritten = VENVS_DIR / f"requirements-{root.name}.txt"
            rewritten.parent.mkdir(parents=True, exist_ok=True)
            rewritten.write_text("\n".join(local) + "\n")
            requirements += ["-r", str(rewritten), "-e", str(sdk)]
        else:
            requirements += ["-r", str(candidate)]
    pyproject = root / "pyproject.toml"
    # a pyproject may only configure tools (pytest...): only a [project] is installable
    if pyproject.exists() and "project" in tomllib.loads(pyproject.read_text()):
        dependencies = (
            tomllib.loads(pyproject.read_text()).get("project", {}).get("dependencies", [])
        )
        if sdk and any(d.strip().startswith("connectors-sdk") for d in dependencies):
            # its pyproject takes the SDK from GitHub's master, whose pycti pin may differ: its
            # other dependencies, the checkout's SDK, then the connector without dependencies
            local = [d for d in dependencies if not d.strip().startswith("connectors-sdk")]
            rewritten = VENVS_DIR / f"requirements-{root.name}-pyproject.txt"
            rewritten.parent.mkdir(parents=True, exist_ok=True)
            rewritten.write_text("\n".join(local) + "\n")
            requirements += ["-r", str(rewritten)]
            if str(sdk) not in requirements:
                requirements += ["-e", str(sdk)]
        else:
            requirements += ["-e", str(root)]
    if not requirements:
        raise RunnerError(f"No requirements.txt or pyproject.toml in {root}")
    # httplib2 (Google API clients) only goes through HTTP(S)_PROXY with PySocks installed
    return [*requirements, "pysocks"]


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
    if component.kind == "connector":
        return {
            "OPENCTI_URL": profile.opencti_url,
            "OPENCTI_TOKEN": profile.opencti_token,
            "CONNECTOR_ID": component.component_id,
            "CONNECTOR_TYPE": component.connector_type,
            "CONNECTOR_LOG_LEVEL": log_level,
            # OpenCTI advertises its RabbitMQ by its Docker name: reach it on the platform host
            "MQ_HOST": profile.host or "",
            # Homebrew's libraries (cairo, pango...) for the packages loading them with ctypes
            **({"DYLD_FALLBACK_LIBRARY_PATH": HOMEBREW_LIB} if Path(HOMEBREW_LIB).is_dir() else {}),
        }
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
        [str(component.python), "-u", *component.argv_tail],
        cwd=component.cwd,
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
