"""staticfire command line."""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from staticfire import config, ops, recipes, runner
from staticfire.openaev import OpenAEVError

app = typer.Typer(
    no_args_is_help=True,
    help="Fire OpenAEV injectors and collectors at a real OpenAEV platform and check the results.",
)
profile_app = typer.Typer(no_args_is_help=True, help="Where the platform under test lives.")
mail_app = typer.Typer(no_args_is_help=True, help="What the mail catcher (mailpit) received.")
app.add_typer(profile_app, name="profile")
app.add_typer(mail_app, name="mail")

ProfileOpt = Annotated[
    str | None, typer.Option("--profile", "-p", help="Profile name (default: the current one)")
]


def _profile(name: str | None) -> config.Profile:
    try:
        return config.load_profile(name)
    except config.ConfigError as err:
        typer.secho(str(err), fg="red", err=True)
        raise typer.Exit(2) from err


def _print(data) -> None:
    typer.echo(data if isinstance(data, str) else ops.dumps(data))


def _pairs(values: list[str] | None) -> dict[str, str]:
    pairs = {}
    for value in values or []:
        if "=" not in value:
            raise typer.BadParameter(f"{value!r} is not KEY=VALUE")
        key, val = value.split("=", 1)
        pairs[key] = val
    return pairs


# -- profiles --


@profile_app.command("from-multipass")
def profile_from_multipass(
    vm: str,
    name: Annotated[str | None, typer.Option(help="Profile name (default: the VM name)")] = None,
    deploy_dir: str = "/opt/xtm",
):
    """Create a profile from a liftoff deployment in a multipass VM."""
    profile = config.profile_from_liftoff(name or vm, multipass_vm=vm, deploy_dir=deploy_dir)
    path = config.save_profile(profile)
    _print({"saved": str(path), "profile": profile.public()})


@profile_app.command("from-ssh")
def profile_from_ssh(
    target: Annotated[str, typer.Argument(help="ssh destination, e.g. ubuntu@1.2.3.4")],
    name: Annotated[str, typer.Option(help="Profile name")],
    deploy_dir: str = "/opt/xtm",
):
    """Create a profile from a liftoff deployment reachable over ssh (e.g. a Mars VM)."""
    profile = config.profile_from_liftoff(name, ssh_target=target, deploy_dir=deploy_dir)
    path = config.save_profile(profile)
    _print({"saved": str(path), "profile": profile.public()})


@profile_app.command("set")
def profile_set(
    name: str,
    url: Annotated[str, typer.Option(help="OpenAEV URL")],
    token: Annotated[str, typer.Option(help="OpenAEV admin token", prompt=True, hide_input=True)],
    mailpit_url: Annotated[str | None, typer.Option(help="mailpit HTTP URL")] = None,
    smtp_host: Annotated[str | None, typer.Option(help="SMTP host injectors send to")] = None,
    smtp_port: int = 1025,
):
    """Create or replace a profile for any OpenAEV platform."""
    profile = config.Profile(
        name=name,
        openaev_url=url.rstrip("/"),
        openaev_token=token,
        mailpit_url=mailpit_url,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
    )
    _print({"saved": str(config.save_profile(profile)), "profile": profile.public()})


@profile_app.command("use")
def profile_use(name: str):
    """Make a profile the current one."""
    config.save_profile(config.load_profile(name), make_current=True)
    _print({"current": name})


@profile_app.command("show")
def profile_show(profile: ProfileOpt = None):
    """Show a profile (token hidden)."""
    _print(_profile(profile).public())


@profile_app.command("list")
def profile_list():
    _print({"profiles": config.list_profiles(), "current": config.current_profile_name()})


# -- platform --


@app.command()
def status(profile: ProfileOpt = None):
    """Platform version, registered injectors/collectors, endpoints and agents, local runs."""
    _print(ops.status(_profile(profile)))


# -- components under test --


@app.command()
def up(
    path: Annotated[str, typer.Argument(help="Injector or collector checkout")],
    kind: Annotated[str | None, typer.Option(help="injector or collector")] = None,
    env: Annotated[list[str] | None, typer.Option("--env", "-e", help="KEY=VALUE")] = None,
    pyoaev: Annotated[str | None, typer.Option(help="Local pyoaev checkout to use")] = None,
    reinstall: bool = False,
    restart: bool = True,
    log_level: str = "info",
    timeout: float = 120,
    profile: ProfileOpt = None,
):
    """Install, start and wait for an injector or collector to register."""
    result = ops.component_up(
        _profile(profile),
        path,
        kind=kind,
        env=_pairs(env),
        pyoaev=pyoaev,
        install="always" if reinstall else "auto",
        restart=restart,
        log_level=log_level,
        timeout=timeout,
    )
    _print(result)
    if not result.get("registered", True):
        raise typer.Exit(1)


@app.command()
def down(target: Annotated[str, typer.Argument(help="Run name or checkout path")]):
    """Stop a running injector or collector."""
    _print(ops.component_down(target))


@app.command()
def runs():
    """Injectors and collectors started by staticfire."""
    _print([r.summary() for r in runner.list_runs()])


@app.command()
def logs(
    target: Annotated[str, typer.Argument(help="Run name or checkout path")],
    lines: Annotated[int, typer.Option("--lines", "-n")] = 80,
    grep: str | None = None,
):
    """Tail the log of a run."""
    _print(ops.component_logs(target, lines, grep))


@app.command()
def contracts(
    injector: Annotated[str, typer.Argument(help="Injector id, type or checkout path")],
    profile: ProfileOpt = None,
):
    """Contracts (and their fields) of a registered injector."""
    p = _profile(profile)
    _print(ops.injector_contracts(p, ops.resolve_injector(p, injector)))


# -- injects --


@app.command()
def inject(
    contract: Annotated[str, typer.Argument(help="Injector contract id")],
    content: Annotated[str | None, typer.Option(help="Content JSON, or @file.json")] = None,
    field: Annotated[
        list[str] | None, typer.Option("--set", help="Content field KEY=VALUE (repeatable)")
    ] = None,
    asset: Annotated[list[str] | None, typer.Option(help="Target asset id")] = None,
    asset_group: Annotated[list[str] | None, typer.Option(help="Target asset group id")] = None,
    team: Annotated[list[str] | None, typer.Option(help="Target team id")] = None,
    expect: Annotated[
        list[str] | None, typer.Option(help="Expectation type: DETECTION, PREVENTION...")
    ] = None,
    title: str | None = None,
    timeout: float = 180,
    no_launch: bool = False,
    profile: ProfileOpt = None,
):
    """Create an atomic testing, launch it, wait, and report status/traces/expectations."""
    data = {}
    if content:
        data = json.loads(Path(content[1:]).read_text() if content.startswith("@") else content)
    data.update(_pairs(field))
    _print(
        ops.run_inject(
            _profile(profile),
            contract,
            data,
            assets=asset,
            asset_groups=asset_group,
            teams=team,
            expectations=expect,
            title=title,
            timeout=timeout,
            launch=not no_launch,
        )
    )


@app.command()
def report(
    inject_id: str,
    asset: Annotated[list[str] | None, typer.Option(help="Targeted asset to detail")] = None,
    profile: ProfileOpt = None,
):
    """Status, traces and expectation results of an existing inject."""
    _print(ops.inject_report(_profile(profile), inject_id, asset))


@app.command()
def expectations(
    inject_id: Annotated[str | None, typer.Option("--inject")] = None,
    profile: ProfileOpt = None,
):
    """Pending agent expectations, as collectors receive them (with their signatures)."""
    _print(ops.pending_expectations(_profile(profile), inject_id))


@app.command("agent-expectations")
def agent_expectations(
    asset: Annotated[
        str | None, typer.Option(help="Endpoint (default: first with an agent)")
    ] = None,
    type_: Annotated[list[str] | None, typer.Option("--type", help="DETECTION/PREVENTION")] = None,
    marker: str | None = None,
    profile: ProfileOpt = None,
):
    """Have an agent run a harmless marker command: real expectations for collector tests."""
    _print(ops.agent_expectations(_profile(profile), asset, type_, marker))


@app.command("wait-expectations")
def wait_expectations(
    inject_id: str,
    asset: str,
    source: Annotated[str | None, typer.Option(help="Only count results from this source")] = None,
    timeout: float = 180,
    profile: ProfileOpt = None,
):
    """Wait until the inject's expectations on an asset have results."""
    done, result = ops.wait_expectations(
        _profile(profile), inject_id, asset, source, timeout=timeout
    )
    _print({"answered": done, "expectations": result})
    if not done:
        raise typer.Exit(1)


@app.command()
def scenario(scenario_id: str, timeout: float = 600, profile: ProfileOpt = None):
    """Start a simulation of a scenario (chained ones too) and wait for its injects."""
    _print(ops.launch_scenario(_profile(profile), scenario_id, timeout))


# -- mail --


@mail_app.command("search")
def mail_search(
    query: Annotated[str, typer.Argument(help='mailpit query, e.g. to:"a@b.c" subject:"x"')],
    limit: int = 20,
    profile: ProfileOpt = None,
):
    _print(ops.mail_search(_profile(profile), query, limit))


@mail_app.command("show")
def mail_show(message_id: str, profile: ProfileOpt = None):
    _print(ops.mailpit(_profile(profile)).describe(message_id))


# -- recipes --


@app.command()
def fire(
    recipe: Annotated[str | None, typer.Argument(help="Recipe name, omit to list them")] = None,
    keep: Annotated[bool, typer.Option(help="Leave the components running")] = False,
    injector_path: str | None = None,
    collector_path: str | None = None,
    pyoaev: Annotated[str | None, typer.Option(help="Local pyoaev checkout to use")] = None,
    verdict: Annotated[
        str | None, typer.Option(help="cortex-xdr: prevented, detected or none")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Full JSON report")] = False,
    profile: ProfileOpt = None,
):
    """Run an end-to-end recipe; exits 0 on PASS, 1 otherwise."""
    if not recipe:
        _print(recipes.DESCRIPTIONS)
        return
    if recipe not in recipes.RECIPES:
        raise typer.BadParameter(f"Unknown recipe {recipe}, known: {list(recipes.RECIPES)}")
    fn = recipes.RECIPES[recipe]
    options = {
        "keep": keep,
        "injector_path": injector_path,
        "collector_path": collector_path,
        "pyoaev": pyoaev,
        "verdict": verdict,
    }
    accepted = inspect.signature(fn).parameters
    result = fn(_profile(profile), **{k: v for k, v in options.items() if k in accepted and v})
    _print(result.to_dict() if as_json else result.summary())
    raise typer.Exit(0 if result.verdict == "PASS" else 1)


def main() -> None:
    try:
        app()
    except (ValueError, FileNotFoundError, runner.RunnerError, OpenAEVError) as err:
        typer.secho(str(err), fg="red", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
