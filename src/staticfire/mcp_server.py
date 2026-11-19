"""MCP server exposing staticfire to a model (stdio transport).

Register it with Claude Code:  claude mcp add staticfire -- uv --directory <repo> run staticfire-mcp
Every tool takes an optional ``profile`` (default: the current staticfire profile).
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

from mcp.server.mcpserver import MCPServer

from staticfire import config, ops, recipes, runner

mcp = MCPServer(
    "staticfire",
    instructions=(
        "staticfire runs OpenAEV injectors and collectors from their checkouts against a real "
        "OpenAEV platform (a profile) and checks what they did. Typical flows: fire_recipe for a "
        "ready-made end-to-end test; or component_up + run_inject (+ mail_search) to test an "
        "injector; agent_expectations + component_up + wait_expectations to test a collector. "
        "Call status first to see the platform, endpoints with agents, and what is running."
    ),
)


def _p(profile: str | None) -> config.Profile:
    return config.load_profile(profile)


@mcp.tool()
def status(profile: str | None = None) -> dict:
    """Platform version, registered injectors and collectors, endpoints with their agents,
    mailpit state and the injectors/collectors staticfire is running."""
    return ops.status(_p(profile))


@mcp.tool()
def list_recipes() -> dict:
    """Ready-made end-to-end tests fire_recipe can run."""
    return recipes.DESCRIPTIONS


@mcp.tool()
def fire_recipe(
    recipe: str,
    keep: bool = False,
    injector_path: str | None = None,
    collector_path: str | None = None,
    pyoaev: str | None = None,
    verdict: str | None = None,
    profile: str | None = None,
) -> dict:
    """Run an end-to-end recipe and return its report (verdict PASS/FAIL/ERROR, named checks,
    links and evidence). Paths default to sibling checkouts of the injectors/collectors repos;
    pass a path to test another checkout or branch. pyoaev: local client-python checkout.
    verdict (cortex-xdr): what the scripted XDR reports, prevented, detected or none."""
    fn = recipes.RECIPES[recipe]
    options = {
        "keep": keep,
        "injector_path": injector_path,
        "collector_path": collector_path,
        "pyoaev": pyoaev,
        "verdict": verdict,
    }
    accepted = inspect.signature(fn).parameters
    return fn(_p(profile), **{k: v for k, v in options.items() if k in accepted and v}).to_dict()


@mcp.tool()
def component_up(
    path: str,
    kind: str | None = None,
    env: dict[str, str] | None = None,
    pyoaev: str | None = None,
    reinstall: bool = False,
    timeout: float = 120,
    profile: str | None = None,
) -> dict:
    """Install (own virtualenv), start and wait for an injector or collector checkout to
    register with the platform. env: extra settings such as vendor base URLs. Returns the run
    (pid, log path), the registered entity and, for injectors, their contracts and fields."""
    return ops.component_up(
        _p(profile),
        path,
        kind=kind,
        env=env,
        pyoaev=pyoaev,
        install="always" if reinstall else "auto",
        timeout=timeout,
    )


@mcp.tool()
def component_down(target: str) -> dict:
    """Stop a run (run name like injector-email-smtp, or the checkout path)."""
    return ops.component_down(target)


@mcp.tool()
def component_logs(target: str, lines: int = 80, grep: str | None = None) -> str:
    """Tail a run's log, optionally filtered by a regex."""
    return ops.component_logs(target, lines, grep)


@mcp.tool()
def list_runs() -> list[dict]:
    """Injectors and collectors started by staticfire, alive or not."""
    return [r.summary() for r in runner.list_runs()]


@mcp.tool()
def injector_contracts(injector: str, profile: str | None = None) -> list[dict]:
    """Contracts of a registered injector (id, type or checkout path) with their fields."""
    p = _p(profile)
    return ops.injector_contracts(p, ops.resolve_injector(p, injector))


@mcp.tool()
def run_inject(
    contract_id: str,
    content: dict[str, Any] | None = None,
    assets: list[str] | None = None,
    asset_groups: list[str] | None = None,
    teams: list[str] | None = None,
    expectations: list[str] | None = None,
    title: str | None = None,
    timeout: float = 180,
    profile: str | None = None,
) -> dict:
    """Create an atomic testing with this contract and content, launch it and wait for it to
    end. expectations: types to attach (DETECTION, PREVENTION); they only become agent
    expectations collectors can answer when assets with agents are targeted. Returns status,
    execution traces, and per asset the traces and expectation results."""
    return ops.run_inject(
        _p(profile),
        contract_id,
        content,
        assets=assets,
        asset_groups=asset_groups,
        teams=teams,
        expectations=expectations,
        title=title,
        timeout=timeout,
    )


@mcp.tool()
def inject_report(
    inject_id: str, assets: list[str] | None = None, profile: str | None = None
) -> dict:
    """Current status, traces and expectation results of an inject."""
    return ops.inject_report(_p(profile), inject_id, assets)


@mcp.tool()
def pending_expectations(inject_id: str | None = None, profile: str | None = None) -> list[dict]:
    """Agent DETECTION/PREVENTION expectations no source answered yet, with their signatures,
    exactly what a collector receives (use the signatures to script vendor fakes)."""
    return ops.pending_expectations(_p(profile), inject_id)


@mcp.tool()
def agent_expectations(
    asset_id: str | None = None,
    types: list[str] | None = None,
    marker: str | None = None,
    profile: str | None = None,
) -> dict:
    """Make an endpoint's agent run a harmless marker command so collectors get real
    expectations (implant process name, dates, addresses) to answer."""
    return ops.agent_expectations(_p(profile), asset_id, types, marker)


@mcp.tool()
def wait_expectations(
    inject_id: str,
    asset_id: str,
    source_id: str | None = None,
    timeout: float = 180,
    profile: str | None = None,
) -> dict:
    """Wait until the inject's DETECTION/PREVENTION expectations on the asset have results
    (only from source_id, a collector id, when given)."""
    done, expectations = ops.wait_expectations(
        _p(profile), inject_id, asset_id, source_id, timeout=timeout
    )
    return {"answered": done, "expectations": expectations}


@mcp.tool()
def launch_scenario(scenario_id: str, timeout: float = 600, profile: str | None = None) -> dict:
    """Start a simulation of a scenario (chained workflows included) and wait for its
    injects to be executed."""
    return ops.launch_scenario(_p(profile), scenario_id, timeout)


@mcp.tool()
def mail_search(query: str, limit: int = 20, profile: str | None = None) -> list[dict]:
    """Messages the mail catcher received, e.g. query 'to:"a@b.c" subject:"x"'."""
    return ops.mail_search(_p(profile), query, limit)


def main() -> None:
    # One INFO line per platform request would drown the server log
    logging.getLogger("httpx").setLevel(logging.WARNING)
    mcp.run()


if __name__ == "__main__":
    main()
