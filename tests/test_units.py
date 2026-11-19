import importlib.util
from datetime import UTC
from pathlib import Path

import pytest

from staticfire import config, runner
from staticfire.report import Report

ROOT = Path(__file__).resolve().parents[1]


def _collector_module():
    path = ROOT / "collectors" / "mailpit" / "mailpit_collector" / "__main__.py"
    spec = importlib.util.spec_from_file_location("mailpit_collector_main", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError:
        pytest.skip("pyoaev is only installed in the collector's own environment")
    return module


def _checkout(tmp_path: Path, repo: str, name: str, dockerfile: str | None, pyproject: str) -> Path:
    root = tmp_path / repo / name
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(pyproject)
    if dockerfile is not None:
        (root / "Dockerfile").write_text(dockerfile)
    return root


def test_parse_env_file_keeps_values_with_equal_signs_and_skips_comments():
    env = config.parse_env_file("# c\nA=1\nB='x=y'\n\nC=\"z\"\nnot a line\n")
    assert env == {"A": "1", "B": "x=y", "C": "z"}


def test_detect_reads_module_from_dockerfile_cmd(tmp_path):
    root = _checkout(
        tmp_path,
        "injectors",
        "nmap",
        'FROM python\nCMD ["python3", "-m", "nmap.openaev_nmap"]\n',
        '[project]\nname = "x"\n',
    )
    component = runner.detect(root)
    assert (component.kind, component.module) == ("injector", "nmap.openaev_nmap")


def test_detect_falls_back_to_project_scripts_and_kind_from_parent(tmp_path):
    root = _checkout(
        tmp_path,
        "collectors",
        "mailpit",
        None,
        '[project]\nname = "x"\n[project.scripts]\nrun = "mailpit_collector.__main__:main"\n',
    )
    component = runner.detect(root)
    assert (component.kind, component.module) == ("collector", "mailpit_collector.__main__")


def test_detect_refuses_an_unknown_kind(tmp_path):
    root = _checkout(tmp_path, "elsewhere", "x", None, '[project]\nname = "x"\n')
    with pytest.raises(runner.RunnerError):
        runner.detect(root)


def test_component_id_is_stable_per_kind_and_name(tmp_path):
    a = runner.Component("injector", "email-smtp", "/a", "m")
    b = runner.Component("injector", "email-smtp", "/b", "n")
    c = runner.Component("collector", "email-smtp", "/a", "m")
    assert a.component_id == b.component_id != c.component_id


def test_pyoaev_pin_ignores_the_dev_extra_marker(tmp_path):
    root = _checkout(
        tmp_path,
        "injectors",
        "x",
        None,
        '[project]\nname = "x"\ndependencies = ["pyoaev (==3.261118.0); extra != \'dev\'"]\n',
    )
    assert runner._pyoaev_pin(root) == "pyoaev==3.261118.0"


def test_report_verdicts():
    report = Report("r")
    assert report.verdict == "FAIL"  # no check proves nothing
    report.check("a", True)
    assert report.verdict == "PASS"
    report.check("b", False, "why")
    assert report.verdict == "FAIL"
    report.error = "boom"
    assert report.verdict == "ERROR"


def test_collector_parses_openaev_nanosecond_dates():
    module = _collector_module()
    parsed = module._parse_date("2026-11-19T04:27:23.606941587Z")
    assert parsed.tzinfo == UTC
    assert parsed.microsecond == 606941


def test_collector_splits_recipient_lists():
    module = _collector_module()
    assert module._split("a@x.y, b@x.y;c@x.y") == ["a@x.y", "b@x.y", "c@x.y"]
    assert module._split(None) == []
