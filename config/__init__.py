"""
Project configuration and local tool settings.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR / "tools"
RESULTS_DIR = BASE_DIR / "results"
LOCAL_SETTINGS_FILE = Path(__file__).resolve().parent / "local_settings.json"

RUNTIME_DIR = BASE_DIR / "runtime"
SUBFINDER_RUNTIME_HOME = RUNTIME_DIR / "subfinder_home"
SUBFINDER_CONFIG_DIR = SUBFINDER_RUNTIME_HOME / ".config" / "subfinder"
SUBFINDER_CONFIG_FILE = SUBFINDER_CONFIG_DIR / "config.yaml"
SUBFINDER_PROVIDER_CONFIG_FILE = SUBFINDER_CONFIG_DIR / "provider-config.yaml"

ONEFORALL_DIR = TOOLS_DIR / "oneforall"
SUBFINDER_DIR = TOOLS_DIR / "subfinder"
DIRSEARCH_DIR = TOOLS_DIR / "dirsearch"

DNS_TIMEOUT = 3
DNS_THREADS = 50
WILDCARD_TEST_COUNT = 3

PORT_SCAN_THREADS = 200
# Total timeout for one nmap subprocess, not a per-port timeout.
PORT_SCAN_TIMEOUT = 600.0
NMAP_PATH = "nmap"

WEB_FINGERPRINT_TIMEOUT = 600
WEB_FINGERPRINT_NMAP_ARGS = [
    "-Pn",
    "-sV",
    "--version-all",
    "--script",
    "http-title,http-server-header,ssl-cert",
]

DIRSEARCH_TIMEOUT = 1800
DIRSEARCH_THREADS = 8
DIRSEARCH_MAX_WORKERS = 8
DIRSEARCH_DEFAULT_EXTRA_ARGS = [
    "--random-agent",
    "--delay",
    "0.2",
    "--max-rate",
    "3",
    "--retries",
    "1",
    "--exclude-status",
    "404,429,500-999",
]


def get_default_nmap_args() -> list[str]:
    """
    Return platform-friendly default nmap arguments.

    On Windows, `-sT` is more reliable than `-sS` in non-admin environments.
    """
    scan_type = "-sT" if sys.platform.startswith("win") else "-sS"
    return [scan_type, "-Pn", "-T4"]


NMAP_DEFAULT_ARGS = get_default_nmap_args()

PORTS_DIR = Path(__file__).resolve().parent
PORT_PRESETS = {
    "common": {"name": "常见端口", "file": "ports_common.txt"},
    "web": {"name": "Web端口", "file": "ports_web.txt"},
    "high_risk": {"name": "高危端口", "file": "ports_high_risk.txt"},
    "full": {"name": "全端口", "file": "ports_full.txt"},
    "custom": {"name": "自定义", "file": "ports_custom.txt"},
}

DEFAULT_TOOL_SETTINGS = {
    "subfinder": {
        "timeout": 600,
        "use_all": True,
        "silent": True,
        "extra_args": [],
    },
    "oneforall": {
        "timeout": 1800,
        "alive": False,
        "brute": False,
        "fmt": "csv",
        "extra_args": [],
    },
    "nmap": {
        "timeout": PORT_SCAN_TIMEOUT,
        "threads": PORT_SCAN_THREADS,
        "args": list(NMAP_DEFAULT_ARGS),
    },
    "dirsearch": {
        "timeout": DIRSEARCH_TIMEOUT,
        "threads": DIRSEARCH_THREADS,
        "extra_args": list(DIRSEARCH_DEFAULT_EXTRA_ARGS),
    },
}


def load_ports(preset: str = "common") -> list[int]:
    """Load port presets from the config directory."""
    info = PORT_PRESETS[preset]
    filepath = PORTS_DIR / info["file"]
    ports: list[int] = []
    with open(filepath, "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "-" in line:
                start, end = line.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(line))
    return sorted(set(ports))


def load_local_settings() -> dict:
    """Load persisted local settings."""
    if not LOCAL_SETTINGS_FILE.exists():
        return {}

    try:
        with open(LOCAL_SETTINGS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_local_settings(data: dict):
    """Persist local settings."""
    LOCAL_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCAL_SETTINGS_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def get_tool_path(tool_name: str, default: str = "") -> str:
    """Return the configured path for a tool."""
    settings = load_local_settings()
    tool_paths = settings.get("tool_paths", {})
    path = tool_paths.get(tool_name, default)
    return str(path).strip() if path else default


def set_tool_path(tool_name: str, path: str):
    """Persist a tool path override."""
    settings = load_local_settings()
    tool_paths = settings.setdefault("tool_paths", {})
    tool_paths[tool_name] = str(Path(path).expanduser())
    save_local_settings(settings)


def get_tool_settings(tool_name: str) -> dict:
    """Return effective tool settings after local overrides are applied."""
    defaults = DEFAULT_TOOL_SETTINGS.get(tool_name, {})
    settings = load_local_settings()
    overrides = settings.get("tool_settings", {}).get(tool_name, {})

    result = json.loads(json.dumps(defaults))
    for key, value in overrides.items():
        result[key] = value
    return result


def set_tool_settings(tool_name: str, values: dict):
    """Persist tool setting overrides."""
    settings = load_local_settings()
    tool_settings = settings.setdefault("tool_settings", {})
    current = tool_settings.setdefault(tool_name, {})
    for key, value in values.items():
        current[key] = value
    save_local_settings(settings)


def reset_tool_settings(tool_name: str):
    """Remove persisted overrides for a tool."""
    settings = load_local_settings()
    tool_settings = settings.get("tool_settings", {})
    if tool_name in tool_settings:
        del tool_settings[tool_name]
        save_local_settings(settings)


def get_all_tool_settings() -> dict:
    """Return effective settings for every supported tool."""
    return {name: get_tool_settings(name) for name in DEFAULT_TOOL_SETTINGS}


def get_subfinder_runtime_env() -> dict[str, str]:
    """
    Build a project-local runtime environment for Subfinder so it does not rely
    on the current user's home config directory.
    """
    SUBFINDER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    for config_file in (SUBFINDER_CONFIG_FILE, SUBFINDER_PROVIDER_CONFIG_FILE):
        if not config_file.exists():
            config_file.write_text("", encoding="utf-8")

    env = dict(os.environ)
    runtime_home = str(SUBFINDER_RUNTIME_HOME)
    env["HOME"] = runtime_home
    env["USERPROFILE"] = runtime_home
    env["XDG_CONFIG_HOME"] = str(SUBFINDER_RUNTIME_HOME / ".config")
    return env


def get_subfinder_config_args() -> list[str]:
    """Return project-local Subfinder config arguments."""
    get_subfinder_runtime_env()
    return [
        "-config",
        str(SUBFINDER_CONFIG_FILE),
        "-pc",
        str(SUBFINDER_PROVIDER_CONFIG_FILE),
    ]


def ensure_dirs():
    """Ensure required runtime directories exist."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    ONEFORALL_DIR.mkdir(parents=True, exist_ok=True)
    SUBFINDER_DIR.mkdir(parents=True, exist_ok=True)
    DIRSEARCH_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    SUBFINDER_RUNTIME_HOME.mkdir(parents=True, exist_ok=True)
    SUBFINDER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def parse_cli_args(arg_string: str) -> list[str]:
    """Parse an argument string using platform-appropriate shlex rules."""
    text = str(arg_string or "").strip()
    if not text:
        return []
    return shlex.split(text, posix=not sys.platform.startswith("win"))
