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


_registry_cache: dict[str, list[str]] = {}


def published(pkg: str) -> list[str]:
    """Release versions of `pkg` on the registry, prereleases excluded."""
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
    _registry_cache[pkg] = [v for v in (data.get("versions") or {}) if parse(v)]
    return _registry_cache[pkg]


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


# ------------------------------------------------------------------ the bump pass

def _worst_of(advisories: list[dict]) -> str:
    sev = "unknown"
    for a in advisories:
        sev = _worst(sev, a.get("severity") or "unknown")
    return sev


def bump_in_range(root: Path, advisories: list[dict]) -> tuple[list[dict], list[dict], str]:
    """Re-resolve every alerted package inside its declared ranges; keep what helped.

    Returns (bumped, advisories still open, note). `bumped` is one entry per package that
    moved AND cleared at least one advisory; `note` is non-empty only when the pass was
    abandoned, and says why. The lockfile and package.json are exactly as they were
    whenever nothing is kept.

    Two runs of `yarn up -R`, not one. The first moves everything alerted and shows which
    packages actually cleared something. If any moved without clearing anything, the
    snapshot is restored and the second run moves only the helpful ones — a PR that says
    "fixes GHSA-x" must not also carry a bump nobody asked for. Both runs are
    `--mode=update-lockfile`, so nothing is linked and no package script executes.

    A changed package.json abandons the pass. `-R` does not rewrite manifests (measured on
    a direct axios in fundraiser-api: lock moved 1.9.0 -> 1.20.0, manifest byte-identical),
    so if it ever did, the assumption this pass rests on is wrong and it must do nothing.
    """
    pkgs = sorted({a["pkg"] for a in advisories if a.get("pkg")})
    if not pkgs:
        return [], advisories, ""
    lock_path, manifest_path = root / "yarn.lock", root / "package.json"
    lock_before, manifest_before = lock_path.read_bytes(), manifest_path.read_bytes()
    tree_before = lock_versions(lock_path)
    open_before = {(a["pkg"], a["ghsa"]) for a in advisories}

    def restore() -> None:
        lock_path.write_bytes(lock_before)
        manifest_path.write_bytes(manifest_before)

    def attempt(names: list[str]) -> tuple[list[dict] | None, str]:
        proc = run(["yarn", "up", "-R", *names, "--mode=update-lockfile"], root)
        if proc.returncode != 0:
            restore()
            return None, "yarn up -R failed; lockfile restored\n" + (proc.stderr or proc.stdout)[-2000:]
        if manifest_path.read_bytes() != manifest_before:
            restore()
            return None, "yarn up -R rewrote package.json, which it must never do here; restored"
        return audit(root), ""

    after, why = attempt(pkgs)
    if after is None:
        return [], advisories, why
    still = {(a["pkg"], a["ghsa"]) for a in after}
    helpful = sorted({pkg for pkg, ghsa in open_before - still})
    if not helpful:
        restore()
        return [], advisories, ""
    if helpful != pkgs:
        restore()
        after, why = attempt(helpful)
        if after is None:
            return [], advisories, why
        still = {(a["pkg"], a["ghsa"]) for a in after}

    tree_after = lock_versions(lock_path)
    bumped = []
    for pkg in helpful:
        cleared = sorted(g for p_, g in open_before - still if p_ == pkg)
        if not cleared:
            continue
        bumped.append({
            "pkg": pkg,
            "from": sorted(tree_before.get(pkg, set()), key=lambda v: parse(v) or ()),
            "to": sorted(tree_after.get(pkg, set()), key=lambda v: parse(v) or ()),
            "ghsas": set(cleared),
            "severity": _worst_of([a for a in advisories if a["pkg"] == pkg]),
        })
    return bumped, after, ""


def render_bumped(bumped: list[dict]) -> str:
    lines = []
    for b in bumped:
        moved = f"{', '.join(b['from'])} → {', '.join(b['to'])}"
        lines.append(f"- `{b['pkg']}` {moved} ({b['severity']}, "
                     f"{', '.join(sorted(b['ghsas']))})")
    return "\n".join(lines)


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
    ap.add_argument("--root", default=".", help="workspace directory (has package.json)")
    ap.add_argument("--dry-run", action="store_true", help="report the plan, write nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable plan on stdout")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "package.json").is_file():
        print(f"{root}: no package.json", file=sys.stderr)
        return 2

    advisories = audit(root)
    # First pass: move what the declared ranges already allow. Skipped on a dry run, which
    # must not write the lockfile and cannot preview this without doing so.
    bumped, bump_note = [], ""
    if not args.dry_run:
        bumped, advisories, bump_note = bump_in_range(root, advisories)
        if bump_note:
            print(bump_note, file=sys.stderr)
    for b in bumped:
        print(f"  {b['pkg']}: {', '.join(b['from'])} -> {', '.join(b['to'])}  "
              f"[{b['severity']}] {', '.join(sorted(b['ghsas']))}")
    # The tree is re-read after the bump: a resolution's shape depends on which lines are
    # present, and the first pass may have removed or merged some.
    tree = lock_versions(root / "yarn.lock")
    proposals, blocked = plan(advisories, root, tree)

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
        # The first pass's lockfile is still in place and still verified; only the
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
