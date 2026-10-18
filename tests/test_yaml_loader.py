"""Provider-data cache safety, invalidation and instance isolation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from qise.data import yaml_loader
from qise.data.pattern_loader import ThreatPatternLoader
from qise.providers.security_context import SecurityContextProvider


@pytest.mark.parametrize("relative_dir", ["data/threat_patterns", "src/qise/data/threat_patterns"])
def test_all_shipped_threat_patterns_are_valid(relative_dir: str) -> None:
    directory = Path(__file__).resolve().parents[1] / relative_dir
    loader = ThreatPatternLoader(directory)
    assert len(loader.patterns) == len(list(directory.glob("*.yaml")))
    assert any(pattern.id == "TPI-004" for pattern in loader.patterns)


def test_cache_reuses_parse_but_never_mutable_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - params: {allowed: [read]}\n")
    parse = yaml.load
    calls = 0

    def count_parse(*args, **kwargs):
        nonlocal calls
        calls += 1
        return parse(*args, **kwargs)

    monkeypatch.setattr(yaml_loader.yaml, "load", count_parse)
    first = yaml_loader.load_yaml_file(path)
    first["rules"][0]["params"]["allowed"].append("write")
    second = yaml_loader.load_yaml_file(path)
    assert second == {"rules": [{"params": {"allowed": ["read"]}}]}
    assert calls == 1


def test_cache_observes_edit_replacement_and_deletion(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("value: old\n")
    assert yaml_loader.load_yaml_file(path) == {"value": "old"}
    before = path.stat()
    path.write_text("value: new\n")
    # Give the same-size edit a distinct nanosecond timestamp even on fast CI.
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    assert yaml_loader.load_yaml_file(path) == {"value": "new"}
    before = path.stat()
    replacement = tmp_path / "replacement.yaml"
    replacement.write_text("value: alt\n")
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement.replace(path)
    assert yaml_loader.load_yaml_file(path) == {"value": "alt"}
    path.unlink()
    with pytest.raises(FileNotFoundError):
        yaml_loader.load_yaml_file(path)


@pytest.mark.parametrize("loader", [yaml.SafeLoader, getattr(yaml, "CSafeLoader", yaml.SafeLoader)])
def test_both_yaml_loaders_reject_python_tags_and_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader: type,
) -> None:
    monkeypatch.setattr(yaml_loader, "_SAFE_LOADER", loader)
    path = tmp_path / "unsafe.yaml"
    path.write_text("value: !!python/name:builtins.str ''\n")
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml_loader.load_yaml_file(path)
    path.write_text("value: safe\n")
    assert yaml_loader.load_yaml_file(path) == {"value": "safe"}


def test_pattern_instances_and_directory_changes_are_independent(tmp_path: Path) -> None:
    path = tmp_path / "first.yaml"
    path.write_text("id: first\nrule_signatures:\n  - keywords: [original]\n")
    first = ThreatPatternLoader(tmp_path)
    first.patterns[0].rule_signatures[0].keywords.append("mutated")
    second = ThreatPatternLoader(tmp_path)
    assert second.patterns[0].rule_signatures[0].keywords == ["original"]
    (tmp_path / "second.yaml").write_text("id: second\n")
    assert [pattern.id for pattern in ThreatPatternLoader(tmp_path).patterns] == ["first", "second"]
    path.unlink()
    assert [pattern.id for pattern in ThreatPatternLoader(tmp_path).patterns] == ["second"]


def test_security_context_instances_keep_nested_params_independent(tmp_path: Path) -> None:
    (tmp_path / "context.yaml").write_text(
        "id: shell\ntrigger: {tool_patterns: [bash]}\nrules:\n"
        "  - description: Check command\n    params: {allowed: [read]}\n"
    )
    first = SecurityContextProvider(tmp_path)
    first.templates[0].rules[0].params["allowed"].append("write")
    first.templates[0].trigger["tool_patterns"].clear()
    second = SecurityContextProvider(tmp_path)
    assert second.templates[0].rules[0].params == {"allowed": ["read"]}
    assert len(second.match_templates("bash")) == 1
