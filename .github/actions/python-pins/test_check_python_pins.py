from pathlib import Path

import check_python_pins as c


def write(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


def kinds(sites, kind):
    return sorted(s.minor for s in sites if s.kind == kind)


def test_finds_docker_hub_python_image(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.14-slim\nRUN true\n")
    assert kinds(c.collect(tmp_path), "dockerfile") == ["3.14"]


def test_finds_uv_and_nikolaik_python_images(tmp_path):
    write(tmp_path, "Dockerfile", "FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim\n")
    write(tmp_path, "sub/Dockerfile", "FROM nikolaik/python-nodejs:python3.11-nodejs19\n")
    assert kinds(c.collect(tmp_path), "dockerfile") == ["3.11", "3.13"]


def test_ignores_non_python_images_and_stage_aliases(tmp_path):
    write(
        tmp_path,
        "Dockerfile",
        "FROM node:26-alpine AS builder\nFROM python:3.12 AS runtime\nFROM builder\n",
    )
    assert kinds(c.collect(tmp_path), "dockerfile") == ["3.12"]


def test_reads_requires_python_from_every_pyproject(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.14.*"\n')
    write(tmp_path, "backend/pyproject.toml", '[project]\nname="b"\nrequires-python = ">=3.13"\n')
    assert kinds(c.collect(tmp_path), "requires-python") == ["3.13", "3.14"]


def test_reads_dev_pins_and_lockfile(tmp_path):
    write(tmp_path, ".python-version", "3.13\n")
    write(tmp_path, ".tool-versions", "nodejs 20.11.0\npython 3.13.1\n")
    write(tmp_path, "uv.lock", 'version = 1\nrequires-python = ">=3.13"\n')
    sites = c.collect(tmp_path)
    assert kinds(sites, ".python-version") == ["3.13"]
    assert kinds(sites, ".tool-versions") == ["3.13"]
    assert kinds(sites, "uv.lock") == ["3.13"]


def test_reads_ci_and_lint_pins(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml", 'jobs:\n  ci:\n    steps:\n      - with:\n          python-version: "3.13"\n')
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname="a"\nrequires-python = "==3.13.*"\n\n[tool.ruff]\ntarget-version = "py313"\n\n[tool.mypy]\npython_version = "3.13"\n',
    )
    sites = c.collect(tmp_path)
    assert kinds(sites, "ci") == ["3.13"]
    assert kinds(sites, "ruff") == ["3.13"]
    assert kinds(sites, "mypy") == ["3.13"]


def test_python_version_file_input_is_not_a_pin(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml", "      - with:\n          python-version-file: .python-version\n")
    assert kinds(c.collect(tmp_path), "ci") == []


def test_skips_vendored_and_virtualenv_trees(tmp_path):
    write(tmp_path, ".venv/pyproject.toml", '[project]\nname="x"\nrequires-python = ">=3.8"\n')
    write(tmp_path, "node_modules/pkg/Dockerfile", "FROM python:3.8\n")
    assert c.collect(tmp_path) == []


def problems(tmp_path):
    sites = c.collect(tmp_path)
    return c.evaluate(
        sites,
        has_pyproject=(tmp_path / "pyproject.toml").exists(),
        role=c.repo_role(tmp_path),
    )


def test_agreeing_repo_has_no_problems(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.14-slim\n")
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.14.*"\n')
    write(tmp_path, "uv.lock", 'requires-python = "==3.14.*"\n')
    write(tmp_path, ".python-version", "3.14\n")
    assert problems(tmp_path) == []


def test_dockerfile_ahead_of_manifest_is_a_problem(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.14-slim\n")
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.13.*"\n')
    found = [p for p in problems(tmp_path) if p.startswith("Python version disagrees")]
    assert found == ["Python version disagrees: 3.13 in pyproject.toml (requires-python); 3.14 in Dockerfile (dockerfile)"]


def test_floor_form_is_rejected_even_when_it_agrees(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.14-slim\n")
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = ">=3.14"\n')
    assert any("==3.14.*" in p for p in problems(tmp_path))


def test_range_form_is_rejected(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = ">=3.11, <3.12"\n')
    assert any("==3.11.*" in p for p in problems(tmp_path))


def test_missing_requires_python_is_a_problem(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nversion="0"\n')
    assert any("requires-python" in p for p in problems(tmp_path))


def test_both_dev_pins_present_is_a_problem(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.13-slim\n")
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.13.*"\n')
    write(tmp_path, ".python-version", "3.13\n")
    write(tmp_path, ".tool-versions", "python 3.13.1\n")
    assert any(".tool-versions" in p for p in problems(tmp_path))


def test_floating_ci_pin_is_a_problem(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.13.*"\n')
    write(tmp_path, ".github/workflows/q.yaml", "          python-version: 3.x\n")
    assert any("3.x" in p for p in problems(tmp_path))


def test_library_may_keep_a_floor(tmp_path):
    # actionkit is consumed by six repos spanning 3.11 and 3.14. A library pinned to
    # one exact minor cannot satisfy both, so the form rule does not apply to it.
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname="a"\nrequires-python = ">=3.11"\n\n[tool.python-pins]\nrole = "library"\n',
    )
    assert problems(tmp_path) == []


def test_library_still_has_to_agree_with_itself(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:3.11-slim\n")
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname="a"\nrequires-python = ">=3.13"\n\n[tool.python-pins]\nrole = "library"\n',
    )
    assert any(p.startswith("Python version disagrees") for p in problems(tmp_path))


def test_repo_with_no_python_is_clean(tmp_path):
    write(tmp_path, "Dockerfile", "FROM node:26-alpine\n")
    assert problems(tmp_path) == []


def test_main_exit_codes(tmp_path, capsys):
    write(tmp_path, "Dockerfile", "FROM python:3.14-slim\n")
    write(tmp_path, "pyproject.toml", '[project]\nname="a"\nrequires-python = "==3.14.*"\n')
    assert c.main(["--root", str(tmp_path)]) == 0
    write(tmp_path, ".python-version", "3.13\n")
    assert c.main(["--root", str(tmp_path)]) == 1
    assert "3.13" in capsys.readouterr().out
