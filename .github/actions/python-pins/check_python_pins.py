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


REQUIRES_OK_RE = re.compile(r"^==(\d+\.\d+)\.\*$")


def repo_role(root: Path) -> str:
    """`library` opts out of the ==X.Y.* form rule. See docs/python-pins.md."""
    path = root / "pyproject.toml"
    if not path.exists():
        return "application"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return "application"
    return str(data.get("tool", {}).get("python-pins", {}).get("role", "application"))


def evaluate(sites: list[Site], has_pyproject: bool, role: str = "application") -> list[str]:
    """Human-readable problems. Empty list means the repo is consistent."""
    problems: list[str] = []
    if not sites and not has_pyproject:
        return problems

    for s in sites:
        if s.minor is None:
            problems.append(f"{s.path}: {s.kind} value {s.raw!r} names no usable X.Y version")

    if has_pyproject and not any(s.kind == "requires-python" for s in sites):
        problems.append(
            "pyproject.toml: no requires-python. Every manifest states its Python as "
            "==X.Y.* -- a missing floor is a pin nobody can check."
        )

    # A library declares what it supports; its consumers each ship their own runtime,
    # so the form rule does not apply to it. Values still have to agree -- the
    # disagreement check below runs for every role.
    if role != "library":
        for s in sites:
            if s.kind == "requires-python" and not REQUIRES_OK_RE.match(s.raw.replace(" ", "")):
                want = f"=={s.minor}.*" if s.minor else "==X.Y.*"
                problems.append(
                    f"{s.path}: requires-python = {s.raw!r} is a floor, not a pin. "
                    f"Write {want} -- a floor is satisfied by every later Python, which is "
                    f"how seven repos drifted a whole minor without going red."
                )

    by_value: dict[str, list[str]] = {}
    for s in sites:
        if s.minor:
            by_value.setdefault(s.minor, []).append(f"{s.path} ({s.kind})")
    if len(by_value) > 1:
        detail = "; ".join(f"{v} in {', '.join(paths)}" for v, paths in sorted(by_value.items()))
        problems.append(f"Python version disagrees: {detail}")

    dev_pins = {s.kind for s in sites} & {".python-version", ".tool-versions"}
    if len(dev_pins) > 1:
        problems.append(
            ".python-version and .tool-versions both pin Python. Keep one -- "
            "delete .tool-versions unless asdf/mise is genuinely in use here."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repo root to check")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    sites = collect(root)
    role = repo_role(root)
    problems = evaluate(sites, has_pyproject=(root / "pyproject.toml").exists(), role=role)

    if args.json:
        print(json.dumps({"sites": [s._asdict() for s in sites], "problems": problems}, indent=2))
        return 1 if problems else 0

    if not sites:
        print("python-pins: no Python version named anywhere -- nothing to check.")
        return 0

    width = max(len(s.path) for s in sites)
    print(f"python-pins: every site that names a Python version (role: {role})\n")
    for s in sites:
        print(f"  {s.path:<{width}}  {s.kind:<16}  {s.raw:<22}  -> {s.minor or '?'}")
    if not problems:
        print(f"\nOK: all {len(sites)} sites agree.")
        return 0
    print("\nFAIL:")
    for p in problems:
        print(f"  * {p}")
    print("\n  Rule: docs/python-pins.md in WeMoveEU/dependency-policy.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
