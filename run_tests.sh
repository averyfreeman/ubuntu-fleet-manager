#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d .venv ]]; then
    uv venv .venv --managed-python -p 3.12
fi

uv sync
uv run python -m unittest discover -s tests -v
