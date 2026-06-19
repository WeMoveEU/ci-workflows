# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository is a collection of **reusable GitHub Actions workflows** (`on: workflow_call`) shared across WeMoveEU projects. It contains no application code — only workflow definitions in `.github/workflows/`. There are no build, test, or lint commands; "developing" here means editing YAML workflow files and publishing a new version tag.

## How These Workflows Are Consumed

Callers reference workflows by path and **version tag** from their own repos:

```yaml
uses: WemoveEU/ci-workflows/.github/workflows/docker-build.yml@v11
```

- Always pin to a version tag (`@v11`), not a branch.
- Changes are released by pushing a new `vN` tag. The latest tag is v11, which points at the current `main`. Bump the major tag when changing workflow inputs/behavior so callers opt in deliberately.
- On every release, update `README.md` with the new version tag and a short summary of the changes that tag includes, so the README and its version-pinned examples don't drift.

## Workflows

- **docker-build.yml** — Foundational reusable workflow. Builds and pushes a Docker image to GitHub Container Registry (`ghcr.io/<name>`). Key inputs: `dockerfile`, `name` (defaults to `${{github.repository}}`), `dir` (build context), `overlay`, `prepare`, `args`, `production_branch` (default `main`). Optional `personal_token` secret for private repos/submodules.
- **deploy-strapi.yml** — Orchestrates a Strapi deploy by calling `docker-build.yml` twice: backend first (`backend/Dockerfile`, image `<repo>/backend`), then frontend (`frontend/Dockerfile`, image `<repo>/frontend`). Between them, `wait-for-backend` polls the live backend until ready.
- **notify.yml** — Posts a Slack notification (green on success, red on failure) via `slackapi/slack-github-action`. Requires the `slack_webhook_url` secret. Call it as a final step from a caller workflow.
- **python-build.yml** — Builds a Python package with `uv` (`astral-sh/setup-uv` + `uv build`).

## Architecture Notes (the non-obvious parts)

### Image tagging strategy (docker-build.yml)
Tags are computed by `docker/metadata-action` based on git context:
- `feature/*` branches → `feature` tag + branch ref
- Semver tags (`v1.2.3`) → version / major.minor / major tags
- Push to `production_branch` → `latest`
- Push to the default branch when it is *not* the production branch → `staging`

### Production vs. staging gating (deploy-strapi.yml)
The `wait-for-backend` job selects its GitHub Environment dynamically: **production** when on the `vars.CI_PRODUCTION_BRANCH` branch *or* a tag starting with `v`; otherwise **staging**. The health check polls `https://strapi.${{ vars.DOMAIN }}/<deploy_marker>` and only runs when the `deploy_marker` input is provided.

### Overlay pattern
The `overlay` input names an artifact (e.g. env files) that `docker-build.yml` downloads and unpacks into the build context before building, then deletes (`geekyeggo/delete-artifact`). `deploy-strapi.yml` makes overlay names run-unique with `${{ github.run_id }}` (e.g. `backend_env_${{github.run_id}}`) to avoid collisions between concurrent runs.

## Configuration required in *calling* repositories

These are not defined here — callers must supply them:
- **Repository variables**: `vars.CI_PRODUCTION_BRANCH`, `vars.DOMAIN` (used by `deploy-strapi.yml`).
- **Secrets**: `slack_webhook_url` (notify), optional `personal_token` (private repo/submodule access). `GITHUB_TOKEN` is used implicitly for ghcr.io auth.

## Conventions

- `.editorconfig` governs formatting: 2-space indent for YAML, LF line endings, UTF-8.
- `.gitignore` deliberately un-ignores `.github/` — never re-ignore it.
