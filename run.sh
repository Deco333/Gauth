#!/usr/bin/env bash
# Запуск gauth-pc без установки: ./run codes, ./run import ga --qr shot.png …
cd "$(dirname "$0")" || exit 1
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || PY=python
exec "$PY" gauth.py "$@"
