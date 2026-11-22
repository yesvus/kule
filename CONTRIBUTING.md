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
