"""
Project configuration and local tool settings.
"""

from __future__ import annotations

import copy
import json
import os
import shlex
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import yaml
from utils.logger import get_logger
from utils.json_io import atomic_write_json


logger = get_logger(__name__)


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
ONEFORALL_RUNTIME_DIR = RUNTIME_DIR / "oneforall"
ONEFORALL_EXPORTS_DIR = ONEFORALL_RUNTIME_DIR / "exports"

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
_REVERSE_IP = _require_section(_SETTINGS, "reverse_ip")
_PORT_SCAN = _require_section(_SETTINGS, "port_scan")
_WEB_FINGERPRINT = _require_section(_SETTINGS, "web_fingerprint")
_DIRSEARCH = _require_section(_SETTINGS, "dirsearch")
_PORT_PRESETS = _require_section(_SETTINGS, "port_presets")
_SCAN_PRESETS = _require_section(_SETTINGS, "scan_presets")
_TOOL_DEFAULTS = _require_section(_SETTINGS, "tool_defaults")


DNS_TIMEOUT = int(_DNS["timeout"])
DNS_THREADS = int(_DNS["threads"])
WILDCARD_TEST_COUNT = int(_DNS["wildcard_test_count"])
REVERSE_IP_TIMEOUT = int(_REVERSE_IP["timeout"])
REVERSE_IP_TLS_PORTS = [int(item) for item in _REVERSE_IP.get("common_tls_ports", [443, 8443, 9443])]

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

SUBDOMAIN_TOOL_NAMES = ("subfinder", "oneforall")
SCAN_PRESET_DEFAULT = "standard"
_PLATFORM_DEFAULT_NMAP_ARGS_TOKEN = "__PLATFORM_DEFAULT__"
_RUNTIME_TOOL_SETTINGS_STACK: list[dict[str, dict]] = []
_RUNTIME_TOOL_SETTINGS_LOCK = threading.RLock()


def _normalize_preset_tool_settings(tool_name: str, values: dict) -> dict:
    normalized: dict = {}
    for key, value in values.items():
        if key in {"args", "extra_args"}:
            if key == "args" and tool_name == "nmap" and value == _PLATFORM_DEFAULT_NMAP_ARGS_TOKEN:
                values_list = [_PLATFORM_DEFAULT_NMAP_ARGS_TOKEN]
            else:
                if not isinstance(value, list):
                    raise ValueError(f"scan_presets.{tool_name}.{key} must be a list in {SETTINGS_FILE}")
                values_list = [str(item) for item in value]

            expanded: list[str] = []
            for item in values_list:
                if key == "args" and tool_name == "nmap" and item == _PLATFORM_DEFAULT_NMAP_ARGS_TOKEN:
                    expanded.extend(NMAP_DEFAULT_ARGS)
                else:
                    expanded.append(item)
            normalized[key] = expanded
            continue
        normalized[key] = copy.deepcopy(value)
    return normalized


def _build_scan_presets() -> dict[str, dict]:
    presets: dict[str, dict] = {}
    for preset_name, info in _SCAN_PRESETS.items():
        if not isinstance(info, dict):
            raise ValueError(f"scan_presets.{preset_name} must be a mapping in {SETTINGS_FILE}")

        raw_subdomain_tools = info.get("subdomain_tools", list(SUBDOMAIN_TOOL_NAMES))
        if not isinstance(raw_subdomain_tools, list) or not raw_subdomain_tools:
            raise ValueError(
                f"scan_presets.{preset_name}.subdomain_tools must be a non-empty list in {SETTINGS_FILE}"
            )
        subdomain_tools: list[str] = []
        for tool_name in raw_subdomain_tools:
            normalized_name = str(tool_name).strip().lower()
            if normalized_name not in SUBDOMAIN_TOOL_NAMES:
                raise ValueError(
                    f"scan_presets.{preset_name}.subdomain_tools contains unsupported tool: {tool_name}"
                )
            if normalized_name not in subdomain_tools:
                subdomain_tools.append(normalized_name)

        raw_tool_settings = info.get("tool_settings", {})
        if not isinstance(raw_tool_settings, dict):
            raise ValueError(f"scan_presets.{preset_name}.tool_settings must be a mapping in {SETTINGS_FILE}")

        effective_tool_settings = copy.deepcopy(DEFAULT_TOOL_SETTINGS)
        normalized_overrides: dict[str, dict] = {}
        for tool_name, values in raw_tool_settings.items():
            if tool_name not in DEFAULT_TOOL_SETTINGS:
                raise ValueError(f"Unknown tool in scan_presets.{preset_name}: {tool_name}")
            if not isinstance(values, dict):
                raise ValueError(
                    f"scan_presets.{preset_name}.tool_settings.{tool_name} must be a mapping in {SETTINGS_FILE}"
                )
            normalized = _normalize_preset_tool_settings(tool_name, values)
            normalized_overrides[tool_name] = normalized
            effective_tool_settings[tool_name].update(copy.deepcopy(normalized))

        presets[str(preset_name).strip().lower()] = {
            "label": str(info.get("label", preset_name)).strip() or str(preset_name),
            "description": str(info.get("description", "") or "").strip(),
            "subdomain_tools": subdomain_tools,
            "tool_settings": effective_tool_settings,
            "overrides": normalized_overrides,
        }

    if SCAN_PRESET_DEFAULT not in presets:
        raise ValueError(f"scan_presets must include '{SCAN_PRESET_DEFAULT}' in {SETTINGS_FILE}")
    return presets


SCAN_PRESETS = _build_scan_presets()


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
    except Exception as exc:
        logger.warning(f"[yellow]读取本地配置失败，已回退到默认配置: {exc}[/yellow]")
        return {}


def save_local_settings(data: dict):
    """Persist local settings."""
    LOCAL_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(LOCAL_SETTINGS_FILE, data, ensure_ascii=False, indent=2)


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

    with _RUNTIME_TOOL_SETTINGS_LOCK:
        runtime_layers = list(_RUNTIME_TOOL_SETTINGS_STACK)
    for layer in runtime_layers:
        runtime_overrides = layer.get(tool_name, {})
        for key, value in runtime_overrides.items():
            result[key] = copy.deepcopy(value)
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


def normalize_scan_preset_name(preset_name: str | None) -> str:
    """Normalize and validate a scan preset name."""
    candidate = str(preset_name or SCAN_PRESET_DEFAULT).strip().lower()
    if candidate not in SCAN_PRESETS:
        raise ValueError(f"Unknown scan preset: {candidate}")
    return candidate


def list_scan_presets() -> list[str]:
    """Return the built-in scan preset names in configured order."""
    return list(SCAN_PRESETS.keys())


def get_scan_preset(preset_name: str | None = None) -> dict:
    """Return metadata and effective tool settings for a scan preset."""
    name = normalize_scan_preset_name(preset_name)
    return copy.deepcopy(SCAN_PRESETS[name])


def get_scan_preset_tool_settings(preset_name: str | None = None) -> dict[str, dict]:
    """Return effective tool settings for a scan preset."""
    preset = get_scan_preset(preset_name)
    return preset["tool_settings"]


def get_scan_preset_overrides(preset_name: str | None = None) -> dict[str, dict]:
    """Return runtime overrides produced by a scan preset."""
    return get_scan_preset_tool_settings(preset_name)


def get_scan_preset_subdomain_tools(preset_name: str | None = None) -> list[str]:
    """Return the preferred subdomain-tool order for a scan preset."""
    preset = get_scan_preset(preset_name)
    return list(preset["subdomain_tools"])


def resolve_scan_preset_subdomain_tools(
    preset_name: str | None = None,
    available_tools: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Resolve preset-preferred subdomain tools against the available tool set."""
    preferred_tools = get_scan_preset_subdomain_tools(preset_name)
    if available_tools is None:
        return preferred_tools

    normalized_available = [str(name).strip().lower() for name in available_tools if str(name).strip()]
    selected = [name for name in preferred_tools if name in normalized_available]
    return selected or normalized_available


def merge_tool_setting_layers(*layers: dict[str, dict] | None) -> dict[str, dict]:
    """Merge multiple tool-setting layers, later layers winning per key."""
    merged: dict[str, dict] = {}
    for layer in layers:
        for tool_name, values in (layer or {}).items():
            bucket = merged.setdefault(tool_name, {})
            for key, value in values.items():
                bucket[key] = copy.deepcopy(value)
    return merged


def summarize_scan_preset(preset_name: str | None = None) -> str:
    """Return a short human-readable summary for a preset."""
    preset = get_scan_preset(preset_name)
    settings = preset["tool_settings"]
    subfinder = settings["subfinder"]
    oneforall = settings["oneforall"]
    nmap = settings["nmap"]
    dirsearch = settings["dirsearch"]
    nmap_retries = "default"
    nmap_args = list(nmap.get("args", []))
    if "--max-retries" in nmap_args:
        index = nmap_args.index("--max-retries")
        if index + 1 < len(nmap_args):
            nmap_retries = str(nmap_args[index + 1])
    dirsearch_rate = "default"
    dirsearch_args = list(dirsearch.get("extra_args", []))
    if "--max-rate" in dirsearch_args:
        index = dirsearch_args.index("--max-rate")
        if index + 1 < len(dirsearch_args):
            dirsearch_rate = str(dirsearch_args[index + 1])
    return (
        f"tools={','.join(preset['subdomain_tools'])} ; "
        f"subfinder timeout={subfinder.get('timeout')}s use_all={subfinder.get('use_all')} ; "
        f"oneforall timeout={oneforall.get('timeout')}s brute={oneforall.get('brute')} ; "
        f"nmap timeout={nmap.get('timeout')}s retries={nmap_retries} ; "
        f"dirsearch threads={dirsearch.get('threads')} rate={dirsearch_rate}"
    )


@contextmanager
def override_tool_settings(overrides: dict[str, dict] | None):
    """Temporarily apply in-process tool setting overrides."""
    normalized = {
        tool_name: copy.deepcopy(values)
        for tool_name, values in (overrides or {}).items()
        if values
    }
    if not normalized:
        yield
        return

    with _RUNTIME_TOOL_SETTINGS_LOCK:
        _RUNTIME_TOOL_SETTINGS_STACK.append(normalized)

    try:
        yield
    finally:
        with _RUNTIME_TOOL_SETTINGS_LOCK:
            for index in range(len(_RUNTIME_TOOL_SETTINGS_STACK) - 1, -1, -1):
                if _RUNTIME_TOOL_SETTINGS_STACK[index] is normalized:
                    del _RUNTIME_TOOL_SETTINGS_STACK[index]
                    break


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
    ONEFORALL_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    ONEFORALL_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)


def parse_cli_args(arg_string: str) -> list[str]:
    """Parse an argument string using platform-appropriate shlex rules."""
    text = str(arg_string or "").strip()
    if not text:
        return []
    return shlex.split(text, posix=not sys.platform.startswith("win"))
