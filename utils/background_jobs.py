"""
Background job helpers for long-running scans.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import config

from .json_io import atomic_write_json, load_json_file


def get_jobs_dir() -> Path:
    """Return the runtime jobs directory, creating it when needed."""
    config.ensure_dirs()
    jobs_dir = config.RUNTIME_DIR / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    return jobs_dir


def create_background_job(prefix: str = "scan", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a background job directory and initial status file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    job_id = f"{prefix}_{timestamp}_{uuid4().hex[:6]}"
    job_dir = get_jobs_dir() / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    status_path = job_dir / "status.json"
    log_path = job_dir / "scan.log"
    command_path = job_dir / "command.txt"

    status_payload = {
        "job_id": job_id,
        "status": "created",
        "created_at": datetime.now().isoformat(),
        "job_dir": str(job_dir),
        "log_path": str(log_path),
        "command_path": str(command_path),
    }
    if metadata:
        status_payload.update(metadata)

    atomic_write_json(status_path, status_payload, ensure_ascii=False, indent=2)
    return {
        "job_id": job_id,
        "job_dir": job_dir,
        "status_path": status_path,
        "log_path": log_path,
        "command_path": command_path,
    }


def update_background_job(status_path: Path | str, **fields: Any) -> dict[str, Any]:
    """Update a background job status file atomically."""
    path = Path(status_path)
    if path.exists():
        try:
            data = load_json_file(path)
        except Exception:
            data = {}
    else:
        data = {}

    data.update({key: value for key, value in fields.items() if value is not None})
    atomic_write_json(path, data, ensure_ascii=False, indent=2)
    return data


def stringify_command(command: list[str]) -> str:
    """Render a human-readable command string for logs and status files."""
    if sys.platform.startswith("win"):
        return subprocess.list2cmdline(command)
    if hasattr(shlex, "join"):
        return shlex.join(command)
    return " ".join(command)


def launch_background_command(
    command: list[str],
    job: dict[str, Any],
    *,
    cwd: Path | str | None = None,
) -> dict[str, Any]:
    """Launch a detached child process and update the job metadata."""
    command_text = stringify_command(command)
    Path(job["command_path"]).write_text(command_text + "\n", encoding="utf-8")

    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": None,
        "stderr": subprocess.STDOUT,
        "cwd": str(cwd) if cwd else None,
    }

    if os.name == "nt":
        creationflags = 0
        if hasattr(subprocess, "DETACHED_PROCESS"):
            creationflags |= subprocess.DETACHED_PROCESS
        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP
        popen_kwargs["creationflags"] = creationflags
    else:
        popen_kwargs["start_new_session"] = True

    with open(job["log_path"], "a", encoding="utf-8") as logfile:
        popen_kwargs["stdout"] = logfile
        process = subprocess.Popen(command, **popen_kwargs)

    update_background_job(
        job["status_path"],
        status="starting",
        pid=process.pid,
        started_at=datetime.now().isoformat(),
        command=command,
        command_text=command_text,
        cwd=str(cwd) if cwd else "",
    )

    launched = dict(job)
    launched["pid"] = process.pid
    launched["command"] = command
    launched["command_text"] = command_text
    return launched
