"""
Optional Python startup hook for the vendored OneForAll runtime.
"""

from __future__ import annotations

from sqlite_compat import ensure_sqlite3


SQLITE_BACKEND = ensure_sqlite3()
