#!/usr/bin/env bash
set -eufo pipefail
cd "$(dirname "$0")/.."
python3 -m venv --copies --upgrade --upgrade-deps .venv
echo "Venv is ready"
