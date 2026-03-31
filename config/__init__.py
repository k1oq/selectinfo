"""
Project configuration and local tool settings.
"""

from __future__ import annotations

import copy
import json
import os
import shlex
import sys
from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(__file__).resolve().parent
SETTINGS_FILE = CONFIG_DIR / "settings.yaml"

TOOLS_DIR = BASE_DIR / "tools"
RESULTS_DIR = BASE_DIR / "results"
LOCAL_SETTINGS_FILE = CONFIG_DIR / "local_settings.json"

RUNTIME_DIR = BASE_DIR / "runtime"
SUBFINDER_RUNTIME_HOME = RUNTIME_DIR / "subfinder_home"
SUBFINDER_CONFIG_DIR = SUBFINDER_RUNTIME_HOME / ".config" / "subfinder"
SUBFINDER_CONFIG_FILE = SUBFINDER_CONFIG_DIR / "config.yaml"
SUBFINDER_PROVIDER_CONFIG_FILE = SUBFINDER_CONFIG_DIR / "provider-config.yaml"

ONEFORALL_DIR = TOOLS_DIR / "oneforall"
SUBFINDER_DIR = TOOLS_DIR / "subfinder"
DIRSEARCH_DIR = TOOLS_DIR / "dirsearch"
PORTS_DIR = CONFIG_DIR


def _load_settings_file() -> dict:
    if not SETTINGS_FILE.exists():
        raise FileNotFoundError(f"Missing settings file: {SETTINGS_FILE}")

    with open(SETTINGS_FILE, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Settings file must contain a top-level mapping: {SETTINGS_FILE}")

    return data


def _require_section(data: dict, key: str) -> dict:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Settings section '{key}' must be a mapping in {SETTINGS_FILE}")
    return value


_SETTINGS = _load_settings_file()
_DNS = _require_section(_SETTINGS, "dns")
_PORT_SCAN = _require_section(_SETTINGS, "port_scan")
_WEB_FINGERPRINT = _require_section(_SETTINGS, "web_fingerprint")
_DIRSEARCH = _require_section(_SETTINGS, "dirsearch")
_PORT_PRESETS = _require_section(_SETTINGS, "port_presets")
_TOOL_DEFAULTS = _require_section(_SETTINGS, "tool_defaults")


DNS_TIMEOUT = int(_DNS["timeout"])
DNS_THREADS = int(_DNS["threads"])
WILDCARD_TEST_COUNT = int(_DNS["wildcard_test_count"])

PORT_SCAN_THREADS = int(_PORT_SCAN["threads"])
# Total timeout for one nmap subprocess, not a per-port timeout.
PORT_SCAN_TIMEOUT = float(_PORT_SCAN["timeout"])
NMAP_PATH = str(_PORT_SCAN["nmap_path"])

WEB_FINGERPRINT_TIMEOUT = int(_WEB_FINGERPRINT["timeout"])
WEB_FINGERPRINT_HOST_TIMEOUT = str(_WEB_FINGERPRINT["host_timeout"])
WEB_FINGERPRINT_SCRIPT_TIMEOUT = str(_WEB_FINGERPRINT["script_timeout"])
WEB_FINGERPRINT_BASE_ARGS = [str(item) for item in _WEB_FINGERPRINT["base_args"]]
WEB_FINGERPRINT_SCRIPTS = [str(item) for item in _WEB_FINGERPRINT["scripts"]]
WEB_FINGERPRINT_NMAP_ARGS = [
    *WEB_FINGERPRINT_BASE_ARGS,
    "--host-timeout",
    WEB_FINGERPRINT_HOST_TIMEOUT,
    "--script-timeout",
    WEB_FINGERPRINT_SCRIPT_TIMEOUT,
    "--script",
    ",".join(WEB_FINGERPRINT_SCRIPTS),
]

DIRSEARCH_TIMEOUT = int(_DIRSEARCH["timeout"])
DIRSEARCH_THREADS = int(_DIRSEARCH["threads"])
DIRSEARCH_MAX_WORKERS = int(_DIRSEARCH["max_workers"])
DIRSEARCH_DEFAULT_EXTRA_ARGS = [str(item) for item in _DIRSEARCH["default_extra_args"]]


def get_default_nmap_args() -> list[str]:
    """
    Return platform-friendly default nmap arguments.

    On Windows, `-sT` is more reliable than `-sS` in non-admin environments.
    """
    default_args = _PORT_SCAN.get("default_args", {})
    if not isinstance(default_args, dict):
        raise ValueError(f"'port_scan.default_args' must be a mapping in {SETTINGS_FILE}")

    key = "windows" if sys.platform.startswith("win") else "default"
    values = default_args.get(key) or default_args.get("default")
    if not isinstance(values, list):
        raise ValueError(f"'port_scan.default_args.{key}' must be a list in {SETTINGS_FILE}")
    return [str(item) for item in values]


NMAP_DEFAULT_ARGS = get_default_nmap_args()

PORT_PRESETS = {
    name: {
        "name": str(info["name"]),
        "file": str(info["file"]),
    }
    for name, info in _PORT_PRESETS.items()
}

DEFAULT_TOOL_SETTINGS = {
    "subfinder": copy.deepcopy(_TOOL_DEFAULTS["subfinder"]),
    "oneforall": copy.deepcopy(_TOOL_DEFAULTS["oneforall"]),
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

    result = copy.deepcopy(defaults)
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
