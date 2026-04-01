"""
SQLite compatibility helpers for the vendored OneForAll runtime.
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
    if hasattr(sqlite3_module, "dbapi2"):
        sys.modules.setdefault("sqlite3.dbapi2", sqlite3_module.dbapi2)
    return "pysqlite3"
