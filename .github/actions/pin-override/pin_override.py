#!/usr/bin/env python3
"""Unstick the advisories Dependabot cannot fix: re-resolve in range first, then pin.

THE FIRST PASS, AND WHY IT COMES FIRST
--------------------------------------
Most of what Dependabot leaves open does not need a resolution at all. It needs the
lockfile to be re-resolved inside the ranges the tree ALREADY declares, which is what
`yarn up -R <pkg>` does and what Dependabot cannot: Dependabot targets one exact version
for a name across the whole tree and gives up when any copy cannot reach it, so a
package installed at 1.x, 2.x and 5.x under three minimatch parents is unfixable to it
forever, though each copy is one patch from clear inside its own range. Measured across
the fleet on 2026-09-11, this pass alone took 220 audit findings to 102, touched no
package.json, and reopened nothing — it also clears the fix a hand-closed Dependabot PR
has taught Dependabot to ignore (fundraiser-api's axios, 29 advisories, one month), because
it never asks Dependabot.

`-R` is load-bearing. `yarn up axios` rewrites the manifest range to the new version; with
`-R` it keeps `^1.3.6` and only moves the lock, for direct and transitive alike. That is
why this pass may include direct dependencies where the resolution pass below may not: it
shadows nothing and pins nothing, it does what a fresh `yarn install` without a lockfile
would have done. Only what clears an advisory is kept; a package that moved without
clearing anything is put back, so the PR carries no unexplained churn.

THE PARENT PASS, BETWEEN THE TWO
--------------------------------
Some advisories survive the first pass for a reason the first pass cannot see: the fix
lives outside the range the PARENT declares, and a newer release of that parent — inside
the parent's own line — already declares a range that admits it. ip-address 9.0.5 sat
under socks@^2.8.3 for two months: socks 2.8.4 wanted ^9.0.5, socks 2.8.10 wants ^10.1.1,
and `yarn up -R socks` moved both in one go. Dependabot never tries this — its security
job rewrites a parent requirement only when the parent is a DIRECT dependency, and socks
is four levels down under node-gyp — so it logged `latest-resolvable-version: 9.0.5` and
gave up, every day. This pass asks the registry which in-line parent release would let
the child reach a fixed version, moves that parent with `yarn up -R`, and keeps it only
if the audit confirms the child's advisory is gone. Same rules as the first pass: lockfile
only, manifest untouched, the parent's compatibility line never crossed.

THE PYTHON PASS (uv)
--------------------
A root holding `pyproject.toml` + `uv.lock` gets the first pass in uv's dialect:
`uv lock --upgrade-package '<pkg><next-line>'` for every package pip-audit reports,
capped at the package's own compatibility line so a floor like `pytest>=8.3.5` never
becomes an 8 -> 9 jump a robot chose. Verified by re-running pip-audit over a fresh
`uv export`; what did not clear is put back and named. Seven fundraiser-api advisories
sat in range for three months for want of exactly this command.

THE SECOND PASS: RESOLUTIONS
----------------------------

THE PROBLEM
-----------
Dependabot fixes a transitive dependency with `yarn up -R <pkg>@<fixed>`. That command
operates on a package NAME across the whole tree, so a single parent pinning that name to
an EXACT version blocks it — even when other copies of the same package could move freely.
Strapi does this everywhere: `@strapi/upload` requires `sharp@0.35.3`, not `^0.35.3`.

The failure then takes one of two shapes, and the quiet one is worse:

  * A dedicated security job fails the run with `security_update_not_possible`. Visible.
  * The daily version-update job logs `No update possible for qs 6.15.3` and reports
    SUCCESS. A qs advisory sat open for a week that way, with a green run history.

Either way the fix a human writes is the same, and always the same shape: a range entry in
`resolutions` that moves the shared lockfile entry. This writes those entries, and only
those.

WHAT IT WILL AND WILL NOT DO
----------------------------
Within the compatibility line only, mirroring the org's no-majors policy — and for 0.x the
MINOR is the line, because 0.21 -> 0.25 is a breaking change the major number alone would
wave through.

Never a direct dependency: Dependabot edits `package.json` perfectly well on its own, and
shadowing a declared dependency with a resolution creates a second pin to maintain forever.

Every proposal is VERIFIED by re-running the audit rather than trusting version arithmetic.
A proposal that does not actually clear its advisory is reverted and reported. A pin that
fixes nothing is worse than no pin: it is one somebody has to explain later.

Anything it cannot do safely it names, so the residue is a short human to-do list instead
of silence.

Usage:
    pin_override.py --root frontend [--dry-run] [--json]

The root may hold package.json (+ yarn.lock), or pyproject.toml + uv.lock, or both. The
npm passes need the repo's own Yarn on PATH; the Python pass needs `uv` on PATH (pip-audit
is fetched by `uv run --with`).

`--dry-run` skips the first pass entirely: it cannot be previewed without running it, and
a dry run must not write the lockfile.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"
GHSA_RE = re.compile(r"GHSA-[0-9a-z-]+", re.I)
PRERELEASE_RE = re.compile(r"[-+]")
# "name@npm:1.2.3" / "@scope/name@npm:1.2.3" -> name, version
DEPENDENT_RE = re.compile(r"^(?P<name>@?[^@]+(?:/[^@]+)?)@(?:npm|workspace|patch):(?P<ver>.+)$")


# ------------------------------------------------------------------ versions

def parse(v: str) -> tuple[int, ...] | None:
    """"1.2.3" -> (1, 2, 3). None for anything that is not a plain release version."""
    if not v or PRERELEASE_RE.search(v):
        return None
    parts = v.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def line_of(v: str) -> tuple[int, ...] | None:
    """The compatibility line a version belongs to.

    (major,) normally, but (0, minor) for 0.x. Under semver a 0.x minor may break, which is
    not theoretical here: esbuild ships 0.21.5 and 0.28.1 in one tree with an advisory
    patched in 0.25.0. Keyed on the major alone, 0.21.5 and 0.25.0 would look like one line
    and this would "fix" the advisory with a breaking bump.
    """
    p = parse(v)
    if p is None:
        return None
    return (0, p[1]) if p[0] == 0 and len(p) > 1 else (p[0],)


def line_name(v: str) -> str:
    line = line_of(v)
    return (".".join(str(n) for n in line) + ".x") if line else v


def in_range(v: str, spec: str) -> bool:
    """Does `v` satisfy a Yarn audit "Vulnerable Versions" spec?

    Those specs are plain comparator sets — "<1.1.17", ">=4.0.0 <5.0.8", "<=9.1.0", or a
    bare "12.0.2" — ANDed by spaces and ORed by "||". No carets or tildes occur in advisory
    ranges, so a small evaluator beats taking a semver dependency inside an action.
    """
    target = parse(v)
    if target is None:
        return False
    return any(_clause_matches(target, c.strip()) for c in spec.split("||"))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


_CMP_RE = re.compile(r"([<>]=?|=)?\s*([0-9][0-9A-Za-z.\-+]*)")


def _clause_matches(target: tuple[int, ...], clause: str) -> bool:
    parts = _CMP_RE.findall(clause)
    if not parts:
        return False
    for op, raw in parts:
        other = parse(raw)
        if other is None:
            return False
        left, right = _pad(target, other)
        op = op or "="
        if op == "<" and not left < right:
            return False
        if op == "<=" and not left <= right:
            return False
        if op == ">" and not left > right:
            return False
        if op == ">=" and not left >= right:
            return False
        if op == "=" and left != right:
            return False
    return True


_PARTIAL_RE = re.compile(r"^v?=?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$")


def _partial(raw: str) -> tuple[tuple[int, int, int], int] | None:
    """"1.2" -> ((1, 2, 0), 2): the version padded to three places, and how many places
    were actually given. x/X/* count as "not given". None for tags, URLs and protocols."""
    m = _PARTIAL_RE.match(raw.strip())
    if not m:
        return None
    nums: list[int] = []
    for part in m.groups():
        if part is None or part in ("x", "X", "*"):
            break
        nums.append(int(part))
    return (tuple(nums + [0] * (3 - len(nums))), len(nums))  # type: ignore[return-value]


def _bump(v: tuple[int, int, int], at: int) -> tuple[int, int, int]:
    """The first version above the range that `v` with `at` given places describes."""
    if at <= 1:
        return (v[0] + 1, 0, 0)
    if at == 2:
        return (v[0], v[1] + 1, 0)
    return (v[0], v[1], v[2] + 1)


def _comparator_matches(t: tuple[int, ...], comp: str) -> bool:
    t3 = tuple(t) + (0,) * (3 - len(t))
    if comp in ("", "*", "x", "X"):
        return True
    op = ""
    for cand in ("^", "~", ">=", "<=", ">", "<", "="):
        if comp.startswith(cand):
            op, comp = cand, comp[len(cand):]
            break
    got = _partial(comp)
    if got is None:
        return False
    v, n = got
    if op == "^":
        if v[0] > 0 or n <= 1:
            hi = (v[0] + 1, 0, 0)
        elif v[1] > 0 or n == 2:
            hi = (0, v[1] + 1, 0)
        else:
            hi = (0, 0, v[2] + 1)
        return v <= t3 < hi
    if op == "~":
        return v <= t3 < (_bump(v, 2) if n >= 2 else _bump(v, 1))
    if op == ">=":
        return t3 >= v
    if op == ">":
        return t3 >= _bump(v, n) if n < 3 else t3 > v
    if op == "<":
        return t3 < v
    if op == "<=":
        return t3 < _bump(v, n) if n < 3 else t3 <= v
    # bare version or x-range: "1.2.3" exact, "1.2" / "1.2.x" / "1" a range
    return v <= t3 < _bump(v, n) if n < 3 else t3 == v


def satisfies(v: str, rng: str) -> bool:
    """Does release `v` satisfy a dependency RANGE as a package.json declares it?

    The shapes a manifest actually contains: `^1.2.3`, `~1.2.3`, comparator sets, x-ranges
    (`1.x`, `1.2.*`, `1`), `*`, hyphen ranges (`1.2 - 2.3`) and `||`. A prerelease never
    satisfies (parse() rejects it, and these trees pin none); a tag, URL or `workspace:`
    protocol never satisfies either, so a parent declaring one is simply never moved.
    """
    target = parse(v)
    if target is None:
        return False
    for alt in rng.split("||"):
        alt = alt.strip()
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hyphen:
            lo, hi = _partial(hyphen.group(1)), _partial(hyphen.group(2))
            if lo is None or hi is None:
                continue
            t3 = tuple(target) + (0,) * (3 - len(target))
            upper_ok = t3 < _bump(hi[0], hi[1]) if hi[1] < 3 else t3 <= hi[0]
            if lo[0] <= t3 and upper_ok:
                return True
            continue
        if all(_comparator_matches(target, c) for c in alt.split()):
            return True
    return False


# ------------------------------------------------------------------ the tree

LOCK_ENTRY_RE = re.compile(r'^"?(?P<desc>[^\n]+?)"?:$')


def lock_versions(lock: Path) -> dict[str, set[str]]:
    """package name -> every version resolved in the lockfile.

    Needed to choose the resolution's shape, which the audit output alone cannot decide:
    whether the package has one compatibility line in the tree, and whether a parent is
    itself present at only one version (see descriptor_for).
    """
    out: dict[str, set[str]] = {}
    if not lock.is_file():
        return out
    for block in lock.read_text().split("\n\n"):
        head = block.splitlines()[0] if block.strip() else ""
        m = LOCK_ENTRY_RE.match(head.strip())
        ver = re.search(r"^  version: (\S+)$", block, re.M)
        if not m or not ver:
            continue
        for desc in m.group("desc").split(", "):
            desc = desc.strip().strip('"')
            if "@npm:" not in desc:
                continue
            name = desc.rsplit("@npm:", 1)[0]
            out.setdefault(name, set()).add(ver.group(1))
    return out


def dependent_name(raw: str) -> str | None:
    """"minimatch@npm:3.1.5" -> "minimatch". None for a workspace or an odd shape."""
    m = DEPENDENT_RE.match(raw.strip())
    if not m or "workspace:" in raw:
        return None
    return m.group("name")


def dependent_pair(raw: str) -> tuple[str, str] | None:
    """"socks@npm:2.8.4" -> ("socks", "2.8.4"). None for a workspace, a patch: descriptor or
    an odd shape — a parent whose installed version is not a plain release cannot be placed
    on a line, so it is never a candidate for the parent pass."""
    m = DEPENDENT_RE.match(raw.strip())
    if not m or "workspace:" in raw or "@patch:" in raw or parse(m.group("ver")) is None:
        return None
    return m.group("name"), m.group("ver")


# ------------------------------------------------------------------ io

def run(cmd: list[str], cwd: Path, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, capture_output=True)


def audit(root: Path) -> list[dict]:
    """Advisories from `yarn npm audit`, deprecation notices dropped.

    Yarn exits non-zero whenever it finds anything, so the return code is not an error.
    A deprecation notice carries a string ID like "@koa/router (deprecation)" and no GHSA
    URL; it is not a vulnerability and must never become a pin.
    """
    proc = run(["yarn", "npm", "audit", "--recursive", "--json"], root)
    out = []
    for raw in proc.stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        kid = row.get("children") or {}
        hit = GHSA_RE.search(kid.get("URL") or "")
        if not hit:
            continue
        out.append({
            "pkg": row.get("value"),
            "ghsa": hit.group(0).upper(),
            "severity": kid.get("Severity") or "unknown",
            "vulnerable": kid.get("Vulnerable Versions") or "",
            "installed": list(kid.get("Tree Versions") or []),
            "dependents": list(kid.get("Dependents") or []),
            "issue": kid.get("Issue") or "",
        })
    return out


_registry_cache: dict[str, dict[str, dict]] = {}


def registry_versions(pkg: str) -> dict[str, dict]:
    """Release version -> abbreviated metadata for `pkg`, prereleases excluded.

    The install-v1 document carries each version's `dependencies`, which is what the
    parent pass reads: it has to know what range socks 2.8.10 declares for ip-address
    before it can say that moving socks would move ip-address out of the advisory.
    """
    if pkg in _registry_cache:
        return _registry_cache[pkg]
    url = f"{REGISTRY}/{urllib.parse.quote(pkg, safe='@')}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.npm.install-v1+json",
        "User-Agent": "wemove-pin-override",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{pkg}: cannot read the registry ({exc})") from exc
    _registry_cache[pkg] = {v: (meta or {}) for v, meta in (data.get("versions") or {}).items()
                            if parse(v)}
    return _registry_cache[pkg]


def published(pkg: str) -> list[str]:
    """Release versions of `pkg` on the registry, prereleases excluded."""
    return list(registry_versions(pkg))


def highest_in_line(pkg: str, installed: str) -> str | None:
    """The newest release sharing `installed`'s line, or None if that is `installed`."""
    want = line_of(installed)
    if want is None:
        return None
    same = [v for v in published(pkg) if line_of(v) == want]
    if not same:
        return None
    best = max(same, key=parse)
    return best if parse(best) > parse(installed) else None


# ------------------------------------------------------------------ planning

SEV_RANK = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "info": 0,
            "unknown": -1}


def _worst(a: str, b: str) -> str:
    return a if SEV_RANK.get(a, -1) >= SEV_RANK.get(b, -1) else b


def direct_deps(root: Path) -> set[str]:
    pkg = json.loads((root / "package.json").read_text())
    names: set[str] = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        names |= set((pkg.get(field) or {}).keys())
    return names


def descriptor_for(pkg: str, installed: str, dependents: list[str],
                   tree: dict[str, set[str]]) -> tuple[str | None, str]:
    """The `resolutions` key for one (package, line), or (None, why-not).

    UNSCOPED when the package has a single compatibility line in the tree. qs was pinned
    exactly by some twenty @strapi/* packages that Yarn had deduped onto ONE lockfile
    entry, so a scoped `@strapi/admin/qs` would have forked a second entry and left the
    vulnerable version in place for the other nineteen. Unscoped moves the shared entry.

    SCOPED TO THE PARENT NAME when several lines coexist and exactly one parent pulls the
    vulnerable one, and that parent is itself present at a single version. undici ships
    6.28.0 (pinned exactly by @strapi/core, and not in the advisory) alongside 7.28.0 (from
    cheerio, which declares ^7.19.0 and would happily take the fix). `cheerio/undici`
    moves only the vulnerable copy. The key deliberately carries no parent VERSION, so it
    keeps working when cheerio bumps.

    REFUSED when the parent itself has several versions in the tree. brace-expansion is
    pulled by minimatch 3.1.5 (^1.1.7), 9.0.9 (^2.0.2) and 10.2.5 (^5.0.5) at once, so
    `minimatch/brace-expansion` would drag all three lines onto one version, and the only
    correct key embeds a parent version that rots the next time minimatch moves. That is a
    human's call, not a robot's.
    """
    lines = {line_of(v) for v in tree.get(pkg, set())} - {None}
    if len(lines) <= 1:
        return pkg, ""

    parents = sorted({n for n in (dependent_name(d) for d in dependents) if n})
    if not parents:
        return None, f"{line_name(installed)} coexists with other lines, no named parent"
    if len(parents) > 1:
        return None, (f"{line_name(installed)} is pulled by several parents "
                      f"({', '.join(parents[:3])})")
    parent = parents[0]
    if len(tree.get(parent, set())) > 1:
        return None, (f"{parent} is itself in the tree at "
                      f"{len(tree[parent])} versions — needs a versioned resolution")
    return f"{parent}/{pkg}", ""


def plan(advisories: list[dict], root: Path,
         tree: dict[str, set[str]]) -> tuple[list[dict], list[dict]]:
    """Split the advisories into (fixable by a resolution, left for a human).

    Keyed on (package, line): several advisories on one line collapse into the single
    resolution that clears them all, which is why the target is "newest in the line"
    rather than any one advisory's first patched version.
    """
    direct = direct_deps(root)
    proposals: dict[tuple[str, tuple], dict] = {}
    blocked: list[dict] = []

    for adv in advisories:
        pkg = adv["pkg"]
        if pkg in direct:
            blocked.append({**adv, "why": "direct dependency — Dependabot can bump it"})
            continue
        for installed in [v for v in adv["installed"] if in_range(v, adv["vulnerable"])]:
            line = line_of(installed)
            target = highest_in_line(pkg, installed) if line else None
            if target is None or in_range(target, adv["vulnerable"]):
                blocked.append({**adv, "installed_one": installed,
                                "why": f"no fix inside the {line_name(installed)} line"})
                continue
            key, why = descriptor_for(pkg, installed, adv["dependents"], tree)
            if key is None:
                blocked.append({**adv, "installed_one": installed, "why": why})
                continue
            slot = proposals.get((pkg, line))
            if slot is None:
                slot = proposals[(pkg, line)] = {
                    "pkg": pkg, "line": line, "installed": installed, "key": key,
                    "target": target, "ghsas": set(), "severity": "unknown"}
            if parse(target) > parse(slot["target"]):
                slot["target"] = target
            slot["ghsas"].add(adv["ghsa"])
            slot["severity"] = _worst(slot["severity"], adv["severity"])

    return sorted(proposals.values(), key=lambda p: p["pkg"]), blocked


# ------------------------------------------------------------------ the bump passes

def _worst_of(advisories: list[dict]) -> str:
    sev = "unknown"
    for a in advisories:
        sev = _worst(sev, a.get("severity") or "unknown")
    return sev


class _Snapshot:
    """The lockfile and manifest as they were, so a pass can put them back byte for byte."""

    def __init__(self, root: Path):
        self.lock, self.manifest = root / "yarn.lock", root / "package.json"
        self.lock_before = self.lock.read_bytes()
        self.manifest_before = self.manifest.read_bytes()

    def restore(self) -> None:
        self.lock.write_bytes(self.lock_before)
        self.manifest.write_bytes(self.manifest_before)

    def manifest_changed(self) -> bool:
        return self.manifest.read_bytes() != self.manifest_before


def _reresolve(root: Path, names: list[str], snap: _Snapshot) -> tuple[list[dict] | None, str]:
    """`yarn up -R` the named packages, lockfile only, and audit the result.

    (None, why) with everything restored when yarn fails or — the assumption every bump
    pass rests on — package.json changed. `-R` does not rewrite manifests (measured on a
    direct axios in fundraiser-api: lock moved 1.9.0 -> 1.20.0, manifest byte-identical),
    so if it ever does, the pass must do nothing rather than guess. `--mode=update-lockfile`
    means nothing is linked and no package script executes.
    """
    proc = run(["yarn", "up", "-R", *names, "--mode=update-lockfile"], root)
    if proc.returncode != 0:
        snap.restore()
        return None, "yarn up -R failed; lockfile restored\n" + (proc.stderr or proc.stdout)[-2000:]
    if snap.manifest_changed():
        snap.restore()
        return None, "yarn up -R rewrote package.json, which it must never do here; restored"
    return audit(root), ""


def _keep_helpful(root: Path, snap: _Snapshot, advisories: list[dict],
                  targets: dict[str, set[tuple[str, str]]],
                  ) -> tuple[list[str], list[dict], set[tuple[str, str]], str]:
    """Bump every name in `targets`; keep only those that cleared one of their advisories.

    `targets` maps a package to re-resolve -> the (pkg, ghsa) advisories it is meant to
    clear: its own for the first pass, its child's for the parent pass. Two runs of
    `yarn up -R`, not one. The first moves everything and shows which names actually
    cleared something; if any moved without clearing, the snapshot is restored and the
    second run moves only the helpful ones — a PR that says "fixes GHSA-x" must not also
    carry a bump nobody asked for.

    Returns (helpful names, audit after, advisories cleared, note). No helpful names means
    the files are exactly as they were.
    """
    names = sorted(targets)
    open_before = {(a["pkg"], a["ghsa"]) for a in advisories}
    after, why = _reresolve(root, names, snap)
    if after is None:
        return [], advisories, set(), why
    cleared = open_before - {(a["pkg"], a["ghsa"]) for a in after}
    helpful = [n for n in names if targets[n] & cleared]
    if not helpful:
        snap.restore()
        return [], advisories, set(), ""
    if helpful != names:
        snap.restore()
        after, why = _reresolve(root, helpful, snap)
        if after is None:
            return [], advisories, set(), why
        cleared = open_before - {(a["pkg"], a["ghsa"]) for a in after}
    return helpful, after, cleared, ""


def _moved(before: dict[str, set[str]], after: dict[str, set[str]],
           pkg: str) -> tuple[list[str], list[str]]:
    key = lambda v: parse(v) or ()  # noqa: E731
    return (sorted(before.get(pkg, set()), key=key), sorted(after.get(pkg, set()), key=key))


def bump_in_range(root: Path, advisories: list[dict]) -> tuple[list[dict], list[dict], str]:
    """Re-resolve every alerted package inside its declared ranges; keep what helped.

    Returns (bumped, advisories still open, note). `bumped` is one entry per package that
    moved AND cleared at least one advisory; `note` is non-empty only when the pass was
    abandoned, and says why. The lockfile and package.json are exactly as they were
    whenever nothing is kept.
    """
    targets: dict[str, set[tuple[str, str]]] = {}
    for a in advisories:
        if a.get("pkg"):
            targets.setdefault(a["pkg"], set()).add((a["pkg"], a["ghsa"]))
    if not targets:
        return [], advisories, ""
    snap = _Snapshot(root)
    tree_before = lock_versions(snap.lock)
    helpful, after, cleared, note = _keep_helpful(root, snap, advisories, targets)
    if not helpful:
        return [], advisories, note
    tree_after = lock_versions(snap.lock)
    bumped = []
    for pkg in helpful:
        frm, to = _moved(tree_before, tree_after, pkg)
        bumped.append({
            "pkg": pkg, "from": frm, "to": to,
            "ghsas": {g for p_, g in cleared if p_ == pkg},
            "severity": _worst_of([a for a in advisories if a["pkg"] == pkg]),
        })
    return bumped, after, ""


def parent_target(parent: str, installed: str, child: str, vulnerable: str) -> str | None:
    """The newest release of `parent` inside `installed`'s line whose declared range for
    `child` resolves to a version outside `vulnerable`, or None.

    "Resolves to" means what Yarn would pick: the newest published `child` satisfying that
    range. A parent release that no longer depends on the child counts too — the
    vulnerable copy leaves the tree with it. This is a filter, not the proof: the audit
    after `yarn up -R` decides what is kept. socks 2.8.4 declared ip-address ^9.0.5 and
    2.8.10 declares ^10.1.1; with ip-address's fix at 10.3.1 this returns 2.8.10.
    """
    want = line_of(installed)
    if want is None:
        return None
    versions = registry_versions(parent)
    newer = [v for v in versions if line_of(v) == want and parse(v) > parse(installed)]
    child_versions = published(child) if newer else []
    for v in sorted(newer, key=parse, reverse=True):
        deps = versions[v].get("dependencies") or {}
        if child not in deps:
            return v
        best = max((c for c in child_versions if satisfies(c, deps[child])),
                   key=parse, default=None)
        if best is not None and not in_range(best, vulnerable):
            return v
    return None


def bump_parents(root: Path, advisories: list[dict]) -> tuple[list[dict], list[dict], str]:
    """Move the PARENT when the child cannot reach its fix inside the parent's range.

    For every open advisory whose vulnerable copy is pulled by a parent that has a newer
    release in its own line declaring a range the fix satisfies, `yarn up -R <parent>`.
    Lockfile only; the parent's line is never crossed; kept only when the audit shows the
    child's advisory gone. Dependabot never attempts this — its security job rewrites a
    parent requirement only for a DIRECT parent — which is how ip-address sat under socks
    for two months with the fix one patch of socks away.

    Returns (bumped, advisories still open, note), like bump_in_range; each `bumped` entry
    also names the child it moved.
    """
    targets: dict[str, set[tuple[str, str]]] = {}
    plans: dict[str, dict] = {}
    for adv in advisories:
        if not any(in_range(v, adv["vulnerable"]) for v in adv["installed"]):
            continue
        for raw in adv["dependents"]:
            pair = dependent_pair(raw)
            if pair is None:
                continue
            parent, pver = pair
            if parent not in plans:
                target = parent_target(parent, pver, adv["pkg"], adv["vulnerable"])
                if target is None:
                    continue
                plans[parent] = {"from": pver, "to": target, "child": adv["pkg"]}
            targets.setdefault(parent, set()).add((adv["pkg"], adv["ghsa"]))
    if not targets:
        return [], advisories, ""
    snap = _Snapshot(root)
    tree_before = lock_versions(snap.lock)
    helpful, after, cleared, note = _keep_helpful(root, snap, advisories, targets)
    if not helpful:
        return [], advisories, note
    tree_after = lock_versions(snap.lock)
    bumped = []
    for parent in helpful:
        child = plans[parent]["child"]
        pf, pt = _moved(tree_before, tree_after, parent)
        cf, ct = _moved(tree_before, tree_after, child)
        mine = cleared & targets[parent]
        bumped.append({
            "pkg": parent, "from": pf, "to": pt,
            "child": child, "child_from": cf, "child_to": ct,
            "ghsas": {g for _, g in mine},
            "severity": _worst_of([a for a in advisories if (a["pkg"], a["ghsa"]) in mine]),
        })
    return bumped, after, ""


def render_bumped(bumped: list[dict]) -> str:
    lines = []
    for b in bumped:
        moved = f"{', '.join(b['from'])} → {', '.join(b['to'])}"
        via = ""
        if b.get("child"):
            via = (f" — parent of `{b['child']}` "
                   f"{', '.join(b['child_from'])} → {', '.join(b['child_to'])}")
        lines.append(f"- `{b['pkg']}` {moved}{via} ({b['severity']}, "
                     f"{', '.join(sorted(b['ghsas']))})")
    return "\n".join(lines)


# ------------------------------------------------------------------ the python pass (uv)

UV_LOCK_RE = re.compile(r'^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', re.M)


def _norm(name: str) -> str:
    """PyPI's normalisation: `Flask_Cors`, `flask.cors` and `flask-cors` are one project."""
    return re.sub(r"[-_.]+", "-", name).lower()


def uv_lock_versions(lock: Path) -> dict[str, set[str]]:
    """package name -> every version in uv.lock (there is normally one per name)."""
    out: dict[str, set[str]] = {}
    if not lock.is_file():
        return out
    for name, ver in UV_LOCK_RE.findall(lock.read_text()):
        out.setdefault(_norm(name), set()).add(ver)
    return out


def uv_audit(root: Path) -> list[dict]:
    """pip-audit over a frozen `uv export`: one entry per (package, advisory).

    The export is what the image installs from, so this audits exactly what ships.
    `--no-deps --disable-pip` keeps pip-audit from resolving anything itself; the lock
    already did. pip-audit exits 1 whenever it finds something, so the return code is not
    an error — a body that is not JSON is, and it is raised rather than read as "clean".
    Entries carry the same keys the Yarn audit produces so the reporting code is shared;
    pip-audit publishes no severity, so it is "unknown".
    """
    req = root / ".pin-override-export.txt"
    try:
        proc = run(["uv", "export", "--frozen", "--no-hashes", "--no-emit-project",
                    "-o", str(req)], root)
        if proc.returncode != 0:
            raise SystemExit("uv export failed:\n" + (proc.stderr or proc.stdout)[-2000:])
        proc = run(["uv", "run", "--no-project", "--with", "pip-audit", "pip-audit",
                    "-r", str(req), "--no-deps", "--disable-pip", "--format", "json",
                    "--progress-spinner", "off"], root)
        try:
            data = json.loads(proc.stdout or "")
        except json.JSONDecodeError as exc:
            raise SystemExit("pip-audit produced no JSON:\n"
                             + (proc.stderr or proc.stdout)[-2000:]) from exc
    finally:
        req.unlink(missing_ok=True)
    out = []
    for dep in data.get("dependencies") or []:
        for v in dep.get("vulns") or []:
            ghsa = next((a for a in (v.get("aliases") or []) if a.upper().startswith("GHSA-")),
                        v.get("id") or "")
            out.append({"pkg": _norm(dep["name"]), "installed": [dep["version"]],
                        "ghsa": ghsa.upper(), "fix": list(v.get("fix_versions") or []),
                        "severity": "unknown", "vulnerable": "", "dependents": []})
    return out


def uv_line_bound(installed: str) -> str:
    """The `-P` constraint that keeps `installed` inside its line: "1.9.1" -> "<2",
    "0.21.5" -> "<0.22". A version that cannot be placed on a line gets no bound."""
    line = line_of(installed)
    if line is None:
        return ""
    return f"<{line[0] + 1}" if len(line) == 1 else f"<0.{line[1] + 1}"


def bump_uv_in_range(root: Path) -> tuple[list[dict], list[dict], str]:
    """The first pass in uv's dialect: re-lock every audited package inside its own line.

    `uv lock -P '<pkg><next-line>'` for all of them at once, then keep only those whose
    advisories the second audit no longer lists — two runs, like the Yarn pass, so the PR
    carries no unexplained movement. The bound is the package's compatibility line, so a
    floor like `pytest>=8.3.5` never turns into an 8 -> 9 jump a robot chose; that stays a
    person's call. pyproject.toml must come back byte-identical: `uv lock -P` never edits
    it, and if it ever did the pass restores everything and stops.

    Returns (bumped, advisories still open, note).
    """
    lock, manifest = root / "uv.lock", root / "pyproject.toml"
    findings = uv_audit(root)
    if not findings:
        return [], [], ""
    lock_before, manifest_before = lock.read_bytes(), manifest.read_bytes()
    tree_before = uv_lock_versions(lock)
    installed = {f["pkg"]: f["installed"][0] for f in findings}
    open_before = {(f["pkg"], f["ghsa"]) for f in findings}

    def restore() -> None:
        lock.write_bytes(lock_before)
        manifest.write_bytes(manifest_before)

    def attempt(names: list[str]) -> tuple[list[dict] | None, str]:
        args: list[str] = []
        for n in names:
            args += ["-P", f"{n}{uv_line_bound(installed[n])}"]
        proc = run(["uv", "lock", *args], root)
        if proc.returncode != 0:
            restore()
            return None, "uv lock failed; lockfile restored\n" + (proc.stderr or proc.stdout)[-2000:]
        if manifest.read_bytes() != manifest_before:
            restore()
            return None, "uv lock rewrote pyproject.toml, which it must never do here; restored"
        return uv_audit(root), ""

    names = sorted(installed)
    after, why = attempt(names)
    if after is None:
        return [], findings, why
    cleared = open_before - {(f["pkg"], f["ghsa"]) for f in after}
    helpful = [n for n in names if any(p_ == n for p_, _ in cleared)]
    if not helpful:
        restore()
        return [], findings, ""
    if helpful != names:
        restore()
        after, why = attempt(helpful)
        if after is None:
            return [], findings, why
        cleared = open_before - {(f["pkg"], f["ghsa"]) for f in after}
    tree_after = uv_lock_versions(lock)
    bumped = []
    for pkg in helpful:
        frm, to = _moved(tree_before, tree_after, pkg)
        bumped.append({"pkg": pkg, "from": frm, "to": to,
                       "ghsas": {g for p_, g in cleared if p_ == pkg}, "severity": "unknown"})
    return bumped, after, ""


def uv_blocked(left: list[dict]) -> list[dict]:
    """What the uv pass could not clear, in the shape render_blocked() expects."""
    out = []
    for f in left:
        ver = f["installed"][0]
        why = ("no fixed version published" if not f.get("fix")
               else f"no fix inside the {line_name(ver)} line")
        out.append({**f, "installed_one": ver, "why": why})
    return out


# ------------------------------------------------------------------ writing

def apply_resolutions(root: Path, entries: dict[str, str]) -> dict[str, str]:
    """Merge entries into package.json resolutions. Returns the previous mapping."""
    path = root / "package.json"
    data = json.loads(path.read_text())
    before = dict(data.get("resolutions") or {})
    merged = dict(before)
    merged.update(entries)
    data["resolutions"] = dict(sorted(merged.items()))
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return before


def restore_resolutions(root: Path, before: dict[str, str]) -> None:
    path = root / "package.json"
    data = json.loads(path.read_text())
    if before:
        data["resolutions"] = before
    else:
        data.pop("resolutions", None)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def install(root: Path) -> tuple[bool, str]:
    """Refresh the lockfile only.

    `--mode=update-lockfile` overrides CI's immutable default on its own and skips the link
    step, so this never builds node_modules and never runs a package build script — worth
    caring about in a job that holds the checkout's credentials.
    """
    proc = run(["yarn", "install", "--mode=update-lockfile"], root)
    return proc.returncode == 0, (proc.stderr or proc.stdout)[-3000:]


# ------------------------------------------------------------------ output

def summarise(applied: list[dict], unresolved: list[dict], blocked: list[dict],
              bumped: list[dict] | None = None) -> str:
    bits = [f"{p['key']} -> ^{p['target']} ({p['severity']}, {len(p['ghsas'])} "
            f"advisor{'y' if len(p['ghsas']) == 1 else 'ies'})" for p in applied]
    out = "; ".join(bits) if bits else "nothing to change"
    if bumped:
        n = sum(len(b["ghsas"]) for b in bumped)
        out = (f"{len(bumped)} package{'s' if len(bumped) != 1 else ''} re-resolved in "
               f"range ({n} advisor{'y' if n == 1 else 'ies'})"
               + ("" if not bits else " | " + out))
    if unresolved:
        out += f" | {len(unresolved)} reverted (did not clear)"
    if blocked:
        out += f" | {len(blocked)} need a human"
    return out


def render_blocked(blocked: list[dict]) -> str:
    seen: dict[tuple, dict] = {}
    for b in blocked:
        seen.setdefault((b["pkg"], b.get("installed_one", ""), b["why"]), b)
    lines = []
    for (pkg, ver, why), b in sorted(seen.items()):
        lines.append(f"- `{pkg}`{(' ' + ver) if ver else ''} [{b['severity']}] — {why}")
    return "\n".join(lines)


def emit(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        if "\n" in value:
            fh.write(f"{name}<<__PIN_EOF__\n{value}\n__PIN_EOF__\n")
        else:
            fh.write(f"{name}={value}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".",
                    help="directory holding package.json and/or pyproject.toml + uv.lock")
    ap.add_argument("--dry-run", action="store_true", help="report the plan, write nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable plan on stdout")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    has_npm = (root / "package.json").is_file()
    has_uv = (root / "pyproject.toml").is_file() and (root / "uv.lock").is_file()
    if not (has_npm or has_uv):
        print(f"{root}: neither package.json nor pyproject.toml + uv.lock", file=sys.stderr)
        return 2

    bumped: list[dict] = []
    blocked: list[dict] = []

    # Python first: independent of the Yarn passes, and skipped on a dry run for the same
    # reason they are — it cannot be previewed without writing the lockfile.
    if has_uv and not args.dry_run:
        uv_bumped, uv_left, uv_note = bump_uv_in_range(root)
        if uv_note:
            print(uv_note, file=sys.stderr)
        for b in uv_bumped:
            print(f"  {b['pkg']}: {', '.join(b['from'])} -> {', '.join(b['to'])}  [uv] "
                  f"{', '.join(sorted(b['ghsas']))}")
        bumped += uv_bumped
        blocked += uv_blocked(uv_left)

    proposals: list[dict] = []
    if has_npm:
        advisories = audit(root)
        if not args.dry_run:
            # First pass: move what the declared ranges already allow. Then the parents of
            # whatever is left, when a newer in-line parent release would let the child
            # reach its fix.
            for step in (bump_in_range, bump_parents):
                moved, advisories, note = step(root, advisories)
                if note:
                    print(note, file=sys.stderr)
                for b in moved:
                    via = f" (via {b['child']})" if b.get("child") else ""
                    print(f"  {b['pkg']}{via}: {', '.join(b['from'])} -> {', '.join(b['to'])}  "
                          f"[{b['severity']}] {', '.join(sorted(b['ghsas']))}")
                bumped += moved
        # The tree is re-read after the bumps: a resolution's shape depends on which lines
        # are present, and the passes above may have removed or merged some.
        tree = lock_versions(root / "yarn.lock")
        proposals, npm_blocked = plan(advisories, root, tree)
        blocked += npm_blocked

    if args.json:
        print(json.dumps({"proposals": proposals, "blocked": blocked},
                         indent=2, default=list))

    for p in proposals:
        print(f"  {p['key']}: {p['installed']} -> ^{p['target']}  "
              f"[{p['severity']}] {', '.join(sorted(p['ghsas']))}")
    for b in blocked:
        print(f"  (human) {b['pkg']} {b.get('installed_one', '')}: {b['why']}")

    emit("blocked", render_blocked(blocked))
    emit("blocked_count", str(len({(b["pkg"], b["why"]) for b in blocked})))
    emit("bumped", render_bumped(bumped))

    if not proposals or args.dry_run:
        emit("changed", "true" if bumped else "false")
        emit("summary", summarise([], [], blocked, bumped))
        if not proposals:
            print("nothing a resolution can fix")
        return 0

    before = apply_resolutions(root, {p["key"]: f"^{p['target']}" for p in proposals})
    ok, log = install(root)
    if not ok:
        restore_resolutions(root, before)
        install(root)
        print("install failed with the proposed resolutions; reverted\n" + log,
              file=sys.stderr)
        # The bump passes' lockfile is still in place and still verified; only the
        # resolutions are gone. Say so rather than reporting the whole run as nothing.
        emit("changed", "true" if bumped else "false")
        emit("summary", summarise([], [], blocked, bumped)
             + " | install failed with the proposed resolutions; reverted")
        return 1

    # Verify against reality, not against the version arithmetic: an advisory we claimed to
    # fix must actually be gone.
    still = {a["ghsa"] for a in audit(root)}
    applied = [p for p in proposals if not (p["ghsas"] & still)]
    unresolved = [p for p in proposals if p["ghsas"] & still]

    if unresolved:
        restore_resolutions(root, before)
        if applied:
            apply_resolutions(root, {p["key"]: f"^{p['target']}" for p in applied})
        ok, log = install(root)
        if not ok:
            restore_resolutions(root, before)
            install(root)
            print("install failed after dropping the unresolved entries; reverted\n" + log,
                  file=sys.stderr)
            emit("changed", "true" if bumped else "false")
            emit("summary", summarise([], [], blocked, bumped)
                 + " | install failed after dropping the unresolved entries; reverted")
            return 1
        for p in unresolved:
            print(f"  reverted {p['key']}: advisories still open after the bump")

    emit("changed", "true" if (applied or bumped) else "false")
    emit("summary", summarise(applied, unresolved, blocked, bumped))
    emit("applied", "\n".join(f"- `{p['key']}` → `^{p['target']}` ({p['severity']}, "
                              f"{', '.join(sorted(p['ghsas']))})" for p in applied))
    print(summarise(applied, unresolved, blocked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
