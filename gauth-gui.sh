#!/usr/bin/env bash
# gauth-pc: открыть графическое окно с кодами 2FA (Linux/macOS).
cd "$(dirname "$0")" || exit 1
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || PY=python
exec "$PY" gauth.py gui "$@"
