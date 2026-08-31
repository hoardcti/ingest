# ingest

<!-- TEMPLATE: one sentence describing what this repository does. -->

## Overview

<!-- TEMPLATE: what problem this solves, and who it is for. -->

## Installation

<!-- TEMPLATE: how to install or deploy. -->

```bash
# TEMPLATE: replace with real commands
```

## Usage

<!-- TEMPLATE: the smallest useful example. -->

```bash
# TEMPLATE: replace with real commands
```

## Development

```bash
# Run the baseline checks this repository inherits from the template
python -m unittest discover -s .github/scripts -p "test_*.py" -v

# Lint and format Python (configured in pyproject.toml)
ruff check . && ruff format --check .

# Audit GitHub Actions workflows for security problems
zizmor --config .github/zizmor.yml .github/workflows/

# Scan the working tree for credentials before committing
python .github/scripts/secret_scan.py --mode tree
```

<!-- TEMPLATE: add this project's own build, test, and lint commands. -->

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All participants are bound by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Never report a vulnerability in a public issue — see [SECURITY.md](SECURITY.md)
for the private disclosure process.

## Licence

Licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE).
