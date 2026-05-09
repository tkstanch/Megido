# Contributing to Megido

Thanks for your interest in contributing to Megido — especially if you are a security researcher using the tool in real assessments or lab environments.

> We welcome contributions that fix issues, improve existing features, and add practical security testing capabilities.

## Responsible Use

Contributions and testing must only target systems you own or systems for which you have explicit authorization.

## Local Development Setup

```bash
git clone https://github.com/tkstanch/Megido.git
cd Megido
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Run the application locally:

```bash
python manage.py migrate
python manage.py runserver
```

Run tests:

```bash
# Repository root currently contains pytest-style test files (test_*.py)
python -m pytest
```

Lint/format:

Megido does not currently define a single required repository-wide lint command.

When submitting code changes, please:

- Follow PEP 8 and keep formatting consistent with nearby code.
- Use a formatter/linter of your choice (for example `black`, `ruff`, or equivalent) and note what you ran in your PR.

## Branching and Pull Request Workflow

1. Fork the repository.
2. Create a feature branch from your fork (`feat/<short-description>` or `fix/<short-description>`).
3. Make focused changes with clear commit messages.
4. Run relevant tests locally.
5. Open a pull request to `tkstanch/Megido`.
6. Collaborate in review and update your PR as requested.

## Coding Standards

- Follow PEP 8 style guidance for Python code.
- Use clear, descriptive names for modules, functions, and test cases.
- Add type hints where reasonable and helpful.
- Keep changes scoped and avoid unrelated refactors.
- Update docs when behavior, setup, or workflows change.

## Adding Scanners, Attack Modules, or Auth Tests

When adding major detection logic, keep modules discoverable and documented.

Suggested convention (update with actual paths as needed):

- Scanner modules: `scanner/<your_module>/` or `megido/modules/<your_module>/`
- Attack automation modules: `megido/modules/<your_module>/attacks/`
- Auth test extensions: `megido/modules/<your_module>/auth_tests/`

Include:

- Detection rationale and references (CWE/OWASP/CVE where relevant)
- Safe defaults to reduce operational risk
- False-positive and false-negative considerations
- Reproducible examples and test coverage when practical

## Reporting False Positives / False Negatives

If Megido reports incorrect results:

1. Open an issue using the **False Positive/Negative** issue template.
2. Share sanitized target details and reproduction steps.
3. Include expected vs actual behavior and payload/request samples.
4. If possible, propose a fix (threshold tuning, signature changes, verification logic updates).

## Issue Triage Labels

Common labels used for triage:

- `good first issue`
- `bug`
- `feature`
- `help wanted`
- `security-research`
- `documentation`

## Proposing Larger Features

For substantial changes (new engines, major architectural shifts, plugin frameworks):

1. Open a Discussion or RFC-style issue first.
2. Describe motivation, scope, tradeoffs, and rollout plan.
3. Align with maintainers before opening a large PR.

## Community Expectations

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and help keep Megido welcoming, constructive, and useful for the security research community.
