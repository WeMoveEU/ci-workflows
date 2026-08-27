#!/usr/bin/env python3
"""Fail when a repo names its Python version in more than one value.

Stdlib only, single file: it runs from a composite action on whatever Python the
runner has. Needs 3.11+ for tomllib; ubuntu-latest ships 3.12.

See WeMoveEU/dependency-policy docs/python-pins.md for the rule this enforces.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", ".next", "out", "dist",
    "build", "target", "site-packages",
}

# Base images whose tag names a Python version. Anything not listed here is not a
# Python pin -- node:26-alpine and nginx:alpine must not become findings.
IMAGE_RES = (
    re.compile(r"^python:(\d+\.\d+)(?:\.\d+)?(?:[-.].*)?$"),
    re.compile(r"^ghcr\.io/astral-sh/uv:python(\d+\.\d+)"),
    re.compile(r"^nikolaik/python-nodejs:python(\d+\.\d+)"),
)
FROM_RE = re.compile(r"^[ \t]*FROM[ \t]+(?:--\S+[ \t]+)*(\S+)", re.IGNORECASE | re.MULTILINE)
TOOL_VERSIONS_RE = re.compile(r"^[ \t]*python[ \t]+(\d+\.\d+)(?:\.\d+)?", re.MULTILINE)
CI_PIN_RE = re.compile(r"^[ \t]*python-version[ \t]*:[ \t]*[\"']?([^\"'\n#]+)", re.MULTILINE)
PY3XX_RE = re.compile(r"^py(\d)(\d+)$")
MINOR_RE = re.compile(r"(\d+)\.(\d+)")


class Site(NamedTuple):
    path: str
    kind: str
    raw: str
    minor: str | None


def _minor(text: str) -> str | None:
    m = MINOR_RE.search(text)
    return f"{m.group(1)}.{m.group(2)}" if m else None


def _walk(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        yield p


def _dockerfile_sites(rel: str, text: str) -> list[Site]:
    out = []
    for image in FROM_RE.findall(text):
        for rx in IMAGE_RES:
            m = rx.match(image)
            if m:
                out.append(Site(rel, "dockerfile", image, m.group(1)))
                break
    return out


def _pyproject_sites(rel: str, text: str) -> list[Site]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [Site(rel, "requires-python", "<unparseable TOML>", None)]
    out = []
    rp = data.get("project", {}).get("requires-python")
    if rp is None:
        rp = data.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python")
    if rp is not None:
        out.append(Site(rel, "requires-python", str(rp), _minor(str(rp))))
    tool = data.get("tool", {})
    tv = tool.get("ruff", {}).get("target-version")
    for value in tv if isinstance(tv, list) else [tv] if tv else []:
        m = PY3XX_RE.match(str(value))
        out.append(Site(rel, "ruff", str(value), f"{m.group(1)}.{m.group(2)}" if m else None))
    mv = tool.get("mypy", {}).get("python_version")
    if mv is not None:
        out.append(Site(rel, "mypy", str(mv), _minor(str(mv))))
    return out


def _workflow_sites(rel: str, text: str) -> list[Site]:
    return [Site(rel, "ci", v.strip(), _minor(v)) for v in CI_PIN_RE.findall(text)]


def collect(root: Path) -> list[Site]:
    """Every place under `root` that names a Python version."""
    sites: list[Site] = []
    for p in _walk(root):
        rel = p.relative_to(root).as_posix()
        name = p.name.lower()
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if name.startswith("dockerfile"):
            sites += _dockerfile_sites(rel, text)
        elif name == "pyproject.toml":
            sites += _pyproject_sites(rel, text)
        elif name == "uv.lock":
            m = re.search(r'^requires-python\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if m:
                sites.append(Site(rel, "uv.lock", m.group(1), _minor(m.group(1))))
        elif name == ".python-version":
            sites.append(Site(rel, ".python-version", text.strip(), _minor(text)))
        elif name == ".tool-versions":
            for v in TOOL_VERSIONS_RE.findall(text):
                sites.append(Site(rel, ".tool-versions", v, _minor(v)))
        elif rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            sites += _workflow_sites(rel, text)
    return sites
