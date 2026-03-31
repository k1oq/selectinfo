"""
Project-local Python startup hooks for the vendored OneForAll runtime.

If the active Python interpreter was built without stdlib sqlite3 support,
fall back to `pysqlite3-binary` so the original OneForAll command line still
works under the same interpreter.
"""

from __future__ import annotations

import importlib
import sys


def ensure_sqlite3() -> str:
    try:
        import sqlite3  # noqa: F401
        return "stdlib"
    except ModuleNotFoundError as exc:
        if exc.name not in {"sqlite3", "_sqlite3"}:
            raise

    sqlite3_module = importlib.import_module("pysqlite3")
    sys.modules["sqlite3"] = sqlite3_module
    return "pysqlite3"


SQLITE_BACKEND = ensure_sqlite3()
