#!/usr/bin/env python3
"""Точка входа: python gauth.py <команда>   (или установленный скрипт `gauth`)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gauth.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
