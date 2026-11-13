#!/bin/sh
# Run every collation experiment end to end.
set -e
cd "$(dirname "$0")/.."
.venv/bin/python -m experiments.run_key_equivalence
.venv/bin/python -m experiments.validate_on_fixtures
.venv/bin/python -m pytest -q -o addopts= tests/test_experiments_collation.py
