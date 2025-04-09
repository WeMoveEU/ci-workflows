# Docker Build and Push GitHub Actions Workflow

This GitHub Actions workflow automates the process of building and pushing Docker images to GitHub Container Registry. It is designed to support multiple image configurations and environments, specifically staging and production.

## Overview

The workflow is triggered via `workflow_call`, which means it can be triggered by other workflows within the repository. It takes parameters to customize the behavior, such as specifying image configurations, the production branch name, and optional secrets for authentication.
Please use a version such as `@v2`

## Inputs

- **dockerfile**: Path to the Dockerfile used for building the image. Default `Dockerfile`

- **name**: Name of the image to be used in the registry.

- **dir**: The root of app sources. Use if you have your app in a project subdirectory, eg. under `/frontend`. Default `.`

- **overlay**: Name of an artifact to unpack over the repository. Use an unique name based on `${{gitlab.run_id}}` to avoid races in using this artifact!

- **prepare**: Commands passed to shell (`sh -c "${{prepare}}"`), after unpacking the overlay, before building image.

- **args**: Docker args (one variable or multiline format), passed to build-args input of _docker-build-push_ action.


- **production_branch**: The name of the production branch. Default is `main`.

- **personal_token**: An optional personal access token used to check out private repositories and submodules.

## Jobs

### Release Job

This job builds and pushes Docker images based on the specified configurations and branch. It includes the following steps:

1. **Checkout Code**: Uses `actions/checkout@v4` to clone the repository and its submodules.

2. **Apply Overlay**: If specified, downloads and deletes an overlay artifact. Useful for applying changes or assets before building. Create overlay with `actions/upload-artifact@v4`. The files will be unpacked from the artifact to project directory. See [this example](https://github.com/WeMoveEU/youmove/blob/main/.github/workflows/release.yml#L23).

3. **Run Prepare Script**: Executes a preparation shell commands if provided in the image configuration.

4. **Generate Image Tag**: Uses `docker/metadata-action@v5` to automatically generate image tags based on branch names and semantic versioning.

5. **Set up Docker Buildx**: Sets up the Docker Buildx environment needed for building multi-platform images.

6. **Login to GitHub Container Registry**: Authenticates using `docker/login-action@v3`.

7. **Build and Push**: Utilizes `docker/build-push-action@v6` to build and push the Docker image to GitHub Container Registry.

## Usage

To use this workflow, call it from another workflow in your repository. Customize the `inputs` based on your project needs, primarily focusing on defining the correct `images` configurations and `production_branch`.

### Sample Workflow Trigger

```yaml
name: Deploy
on:
  push:
    branches:
      - main
      - 'release/*'
jobs:
  release:
    uses: WemoveEU/ci-workflows/.github/workflows/docker-build.yml@v2
    with:
      production_branch: ${{vars.CI_PRODUCTION_BRANCH}}
      dockerfile: server/Dockerfile
      dir: server
      name: crm/server
```

