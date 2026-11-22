# Contributing to Kule

Thanks for your interest in improving Kule.

## Development

Kule uses Python 3.11+ and [FastMCP](https://gofastmcp.com/). The development and test workflow currently supports Linux and macOS. On Windows, use **WSL** and follow the Linux commands; native Windows tests are not supported because the audit implementation uses Unix `fcntl`.

```sh
git clone https://github.com/yesvus/kule.git
cd kule
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest -q
```

## Pull requests

1. Open an issue for substantial design changes so the approach can be discussed.
2. Keep each pull request focused, with relevant tests and a concise description of observable behavior.
3. Document any new configuration option and its secure default.
4. Check that logs, examples, screenshots and fixtures contain no real credentials or private infrastructure details.

The project uses Apache-2.0. By contributing, you agree that your contribution is licensed under the same license.

## Security

Please use the private reporting process in [SECURITY.md](SECURITY.md) for vulnerabilities.

## Issue triage

Use the **Bug report**, **Feature proposal**, or **Maintenance or RFC** issue form. Search for duplicates first and keep sensitive vulnerability reports in [GitHub Security Advisories](https://github.com/yesvus/kule/security/advisories/new).

- The issue form applies `bug`, `enhancement`, or `maintenance`, plus `needs-triage`. These classification labels are used for filtering; no title prefix is required.
- Maintainers assign **one** `area:*` label after triage: `auth`, `host`, `transport`, `audit`, `ci`, `docs`, or `repo`. The dropdown in each form is context for triage, not an automatically assigned label.
- Add `security-review` to changes touching host privileges, execution, enrollment, OAuth, role policy, credentials, or audit controls. A review must happen before implementation or deployment.
- Remove `needs-triage` when scope and security impact are understood; assign an owner when work is accepted, not merely when the issue is filed. Cross-reference related issues instead of duplicating their scope.
- Use priority only when an active maintainer commits to a delivery order; do not create priority labels just to populate every issue.

The repository's label names, descriptions, and colors are maintained in [`.github/labels.json`](.github/labels.json) and synchronized by a main-branch workflow. This workflow does not automatically close, prioritize, or assign issues.
