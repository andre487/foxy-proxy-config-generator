#!/usr/bin/env bash
set -eufo pipefail

export MODE_DEV=1

cd "$(dirname "$0")/../server"
../.venv/bin/python3 app.py
