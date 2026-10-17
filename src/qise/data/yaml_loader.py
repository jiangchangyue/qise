"""Safe YAML loading with bounded, file-versioned caching for provider data."""

from __future__ import annotations

import os
from copy import deepcopy
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# CSafeLoader has the same restricted constructors as SafeLoader; neither
# accepts Python object tags. PyYAML builds without libyaml retain the fallback.
_SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


@lru_cache(maxsize=128)
def _load_version(path: str, version: tuple[int, ...]) -> Any:
    with open(path, encoding="utf-8") as stream:
        return yaml.load(stream, Loader=_SAFE_LOADER)


def yaml_files(directory: str | Path) -> list[os.DirEntry[str]]:
    """List YAML entries once without redundant directory exists/is_dir probes."""
    try:
        with os.scandir(directory) as entries:
            return sorted((entry for entry in entries if fnmatch(entry.name, "*.yaml")), key=lambda entry: entry.name)
    except OSError:
        return []


def load_yaml_file(path: str | Path | os.DirEntry[str]) -> Any:
    """Load current file data, returning an independent object graph each time.

    Stat every lookup so edits, replacement and deletion are visible immediately.
    Include inode/ctime as well as mtime/size to detect atomic replacements and
    same-size edits that preserve mtime. Failed reads/parses are never cached.
    """
    filename = os.path.abspath(path)
    stat = path.stat() if isinstance(path, os.DirEntry) else os.stat(filename)
    version = (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
    return deepcopy(_load_version(filename, version))
