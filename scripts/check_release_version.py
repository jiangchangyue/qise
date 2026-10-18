#!/usr/bin/env python3
"""Validate that Qise release metadata uses one semantic version."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read_toml(path: str) -> dict[str, object]:
    with (ROOT / path).open("rb") as handle:
        return tomllib.load(handle)


def _read_json(path: str) -> dict[str, object]:
    with (ROOT / path).open(encoding="utf-8") as handle:
        return json.load(handle)


def release_versions() -> dict[str, str]:
    pyproject = _read_toml("pyproject.toml")
    cargo = _read_toml("src-tauri/Cargo.toml")
    cargo_lock = _read_toml("src-tauri/Cargo.lock")
    locked_app = next(
        (package for package in cargo_lock.get("package", []) if package.get("name") == "qise-app"),
        None,
    )
    if locked_app is None:
        raise ValueError("src-tauri/Cargo.lock does not define qise-app")
    tauri = _read_json("src-tauri/tauri.conf.json")
    package = _read_json("src-ui/package.json")
    package_lock = _read_json("src-ui/package-lock.json")
    init_text = (ROOT / "src/qise/__init__.py").read_text(encoding="utf-8")
    init_match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
    if init_match is None:
        raise ValueError("src/qise/__init__.py does not define __version__")

    lock_packages = package_lock.get("packages")
    if not isinstance(lock_packages, dict) or not isinstance(lock_packages.get(""), dict):
        raise ValueError('src-ui/package-lock.json does not define packages[""]')

    return {
        "pyproject.toml": str(pyproject["project"]["version"]),  # type: ignore[index]
        "src/qise/__init__.py": init_match.group(1),
        "src-tauri/Cargo.toml": str(cargo["package"]["version"]),  # type: ignore[index]
        "src-tauri/Cargo.lock qise-app": str(locked_app["version"]),
        "src-tauri/tauri.conf.json": str(tauri["version"]),
        "src-ui/package.json": str(package["version"]),
        "src-ui/package-lock.json": str(package_lock["version"]),
        'src-ui/package-lock.json packages[""]': str(lock_packages[""]["version"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected")
    parser.add_argument("--tag")
    args = parser.parse_args()

    try:
        versions = release_versions()
    except (KeyError, TypeError, ValueError) as error:
        print(f"release metadata error: {error}", file=sys.stderr)
        return 1

    release_version = next(iter(versions.values()))
    errors = [
        f"{source} has version {version}, expected {release_version}"
        for source, version in versions.items()
        if version != release_version
    ]

    if args.expected and release_version != args.expected:
        errors.append(f"release version {release_version} does not match expected version {args.expected}")

    if args.tag:
        tag_version = args.tag.removeprefix("v")
        if tag_version != release_version:
            errors.append(f"tag {args.tag} does not match release version {release_version}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"release version: {release_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
