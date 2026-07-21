# Releasing ci-workflows

This repo publishes reusable workflows (`.github/workflows/*.yml`) and composite
actions (`.github/actions/*`) that other WeMove repos call. We version them with
**semver tags plus a floating major tag**, so consumers pin a major and pick up
minor/patch fixes automatically.

## Tagging scheme

For every release, create an **immutable** version tag and move the **floating
major** tag to it:

- `vMAJOR.MINOR.PATCH` — immutable, never moved (e.g. `v14.0.0`).
- `vMAJOR` — floating, always points at the latest `vMAJOR.*` release (e.g. `v14`).

Bump rules:

- **Patch / minor** (backward-compatible fix or additive input): cut
  `vMAJOR.(MINOR|PATCH+1)` and move `vMAJOR` to it. Consumers on `@vMAJOR` get
  it with no PR.
- **Major** (breaking change to inputs/behavior): cut `v(MAJOR+1).0.0` and
  create a new floating `v(MAJOR+1)`. Consumers stay on the old major until they
  opt in; Dependabot opens the major-bump PR for them.

## How consumers pin

Always pin the **floating major**:

```yaml
uses: WeMoveEU/ci-workflows/.github/workflows/docker-build.yml@v14
uses: WeMoveEU/ci-workflows/.github/actions/docker-smoke@v14
```

Dependabot (github-actions ecosystem) leaves `@v14` alone and only opens a PR
when a new major (`v15`) appears — so minor/patch fixes flow in automatically
and only breaking changes require review.

## Cutting a release

```bash
SHA=$(gh api repos/WeMoveEU/ci-workflows/git/ref/heads/main --jq '.object.sha')
# immutable
gh api repos/WeMoveEU/ci-workflows/git/refs -f ref="refs/tags/v14.1.0" -f sha="$SHA"
# move the floating major
gh api -X PATCH repos/WeMoveEU/ci-workflows/git/refs/tags/v14 -F sha="$SHA" -F force=true
```

## History

Tags `v1`–`v13` predate this scheme — they are frozen point releases, not
floating majors. The floating-major convention starts at **`v14`** (the first
release that also ships the `docker-smoke` action). Repos still pinned to older
integer tags keep working; migrate them to `@v14` as they're touched.
