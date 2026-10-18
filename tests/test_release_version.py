from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from base64 import b64encode
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_release_version.py"
KEY_CHECKER = ROOT / "scripts" / "check_updater_signing_key.py"


def run_checker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def run_key_checker(value: str | None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if value is None:
        env.pop("TAURI_SIGNING_PRIVATE_KEY", None)
    else:
        env["TAURI_SIGNING_PRIVATE_KEY"] = value
    return subprocess.run(
        [sys.executable, str(KEY_CHECKER)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_updater_signing_key_checker_accepts_rsign_key() -> None:
    decoded = b"untrusted comment: rsign encrypted secret key\n" + (b"A" * 212)
    result = run_key_checker(b64encode(decoded).decode("ascii"))
    assert result.returncode == 0, result.stderr
    assert "updater signing key format: valid" in result.stdout


def test_updater_signing_key_checker_rejects_extra_terminal_prompt() -> None:
    decoded = b"untrusted comment: rsign encrypted secret key\n" + (b"A" * 212)
    result = run_key_checker(b64encode(decoded).decode("ascii") + "%")
    assert result.returncode == 1
    assert "invalid Base64 character" in result.stderr
    assert "copy the key file directly" in result.stderr


def test_updater_signing_key_checker_rejects_missing_secret() -> None:
    result = run_key_checker(None)
    assert result.returncode == 1
    assert "TAURI_SIGNING_PRIVATE_KEY is not set" in result.stderr


def test_release_versions_are_synchronized() -> None:
    result = run_checker("--expected", "0.2.1")
    assert result.returncode == 0, result.stderr
    assert "release version: 0.2.1" in result.stdout


def test_matching_git_tag_is_accepted() -> None:
    result = run_checker("--tag", "v0.2.1")
    assert result.returncode == 0, result.stderr


def test_mismatched_git_tag_is_rejected() -> None:
    result = run_checker("--tag", "v9.9.9")
    assert result.returncode == 1
    assert "does not match release version 0.2.1" in result.stderr


def test_tauri_updater_configuration_is_complete() -> None:
    tauri_config = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
    capability = json.loads(
        (ROOT / "src-tauri/capabilities/default.json").read_text(encoding="utf-8")
    )
    with (ROOT / "src-tauri/Cargo.toml").open("rb") as handle:
        cargo = tomllib.load(handle)
    lib_source = (ROOT / "src-tauri/src/lib.rs").read_text(encoding="utf-8")

    updater = tauri_config["plugins"]["updater"]
    public_key = updater["pubkey"]

    assert tauri_config["bundle"]["createUpdaterArtifacts"] is True
    assert updater["endpoints"] == [
        "https://github.com/jiangchangyue/qise/releases/latest/download/latest.json"
    ]
    assert isinstance(public_key, str) and public_key.strip()
    assert "placeholder" not in public_key.lower()
    assert updater["windows"]["installMode"] == "passive"
    assert "updater:default" in capability["permissions"]
    assert "process:default" in capability["permissions"]
    assert "tauri-plugin-updater" in cargo["dependencies"]
    assert "tauri-plugin-process" in cargo["dependencies"]
    assert "tauri_plugin_process::init()" in lib_source
    assert "tauri_plugin_updater::Builder::new().build()" in lib_source


def test_desktop_release_workflow_builds_signed_drafts() -> None:
    workflow_path = ROOT / ".github/workflows/desktop-release.yml"
    assert workflow_path.exists()
    workflow = workflow_path.read_text(encoding="utf-8")

    assert 'tags: ["v*"]' in workflow
    assert "contents: write" in workflow
    assert "windows-latest" in workflow
    assert "--bundles nsis" in workflow
    assert "macos-latest" in workflow
    assert "--target aarch64-apple-darwin" in workflow
    assert "TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}" in workflow
    assert (
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD: "
        "${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}" in workflow
    )
    assert "tauri-apps/tauri-action@v0.6.2" in workflow
    assert "tauriScript: npx --prefix src-ui tauri" in workflow
    assert "python scripts/check_updater_signing_key.py" in workflow
    assert "releaseDraft: true" in workflow
    assert "prerelease: false" in workflow
    assert "updaterJsonPreferNsis: true" in workflow
    assert 'scripts/check_release_version.py --tag "${{ github.ref_name }}"' in workflow


def test_windows_test_workflow_never_commits_installers() -> None:
    workflow = (ROOT / ".github/workflows/windows-desktop.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "contents: write" not in workflow
    assert "git commit" not in workflow
    assert "git push" not in workflow
