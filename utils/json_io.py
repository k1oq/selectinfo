"""
Atomic JSON read/write helpers.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_json(path: str | Path, payload: Any, *, ensure_ascii: bool = False, indent: int = 2):
    """
    Atomically replace a JSON file on disk.

    The destination file is only replaced after the new content has been fully
    written and flushed to a temporary file in the same directory.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_file_path = Path(temp_file.name)
            json.dump(payload, temp_file, ensure_ascii=ensure_ascii, indent=indent)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        temp_file_path.replace(destination)
    except Exception:
        if temp_file_path is not None:
            temp_file_path.unlink(missing_ok=True)
        raise


def load_json_file(path: str | Path) -> Any:
    """Read a UTF-8 JSON file from disk."""
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)
