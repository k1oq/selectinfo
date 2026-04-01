"""
Unified tool configuration API shared by MCP and interactive menus.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

import config
from utils import atomic_write_json
from .dirsearch_wrapper import DirsearchTool
from .oneforall_wrapper import OneForAllTool
from .self_check import ToolSelfChecker
from .setup_manager import NmapSetupManager
from .subfinder_wrapper import SubfinderTool


SUPPORTED_TOOLS = ("subfinder", "oneforall", "nmap", "dirsearch")
RESERVED_ARG_TOKENS = {
    "subfinder": {"-d", "-domain", "-silent", "-all", "-config", "-pc"},
    "oneforall": {"--target", "--alive", "--brute", "--fmt", "run"},
    "nmap": set(),
    "dirsearch": set(),
}


class ToolConfigAPI:
    """Tool configuration facade."""

    def __init__(self):
        self.targets = {
            "subfinder": SubfinderTool(),
            "oneforall": OneForAllTool(),
            "nmap": NmapSetupManager,
            "dirsearch": DirsearchTool(),
        }

    def list_tools(self) -> list[str]:
        return list(SUPPORTED_TOOLS)

    def get_tool_info(self, tool_name: str) -> dict[str, Any]:
        self._validate_tool(tool_name)
        target = self.targets[tool_name]
        check_result = ToolSelfChecker().run_all()[tool_name]
        return {
            "name": tool_name,
            "path": check_result.path,
            "installed": check_result.installed,
            "usable": check_result.usable,
            "version": check_result.version,
            "message": check_result.message,
            "expected_location": str(target.get_expected_location()),
            "settings": config.get_tool_settings(tool_name),
        }

    def get_all_tools_info(self) -> dict[str, Any]:
        return {tool_name: self.get_tool_info(tool_name) for tool_name in SUPPORTED_TOOLS}

    def configure_tool_path(self, tool_name: str, path: str) -> dict[str, Any]:
        self._validate_tool(tool_name)
        ok = self.targets[tool_name].configure_path(path)
        return {
            "ok": ok,
            "tool": tool_name,
            "path": path,
            "info": self.get_tool_info(tool_name),
        }

    def set_tool_path(self, tool_name: str, path: str) -> dict[str, Any]:
        return self.configure_tool_path(tool_name, path)

    def update_tool_settings(self, tool_name: str, values: dict[str, Any]) -> dict[str, Any]:
        self._validate_tool(tool_name)
        sanitized = self._sanitize_settings(tool_name, values)
        config.set_tool_settings(tool_name, sanitized)
        return {
            "ok": True,
            "tool": tool_name,
            "updated": sanitized,
            "settings": config.get_tool_settings(tool_name),
        }

    def set_tool_arg_string(self, tool_name: str, arg_string: str) -> dict[str, Any]:
        self._validate_tool(tool_name)
        parsed_args = self.parse_arg_string(arg_string)
        self._validate_reserved_args(tool_name, parsed_args)

        if tool_name == "nmap":
            updated = {"args": parsed_args}
        else:
            updated = {"extra_args": parsed_args}

        result = self.update_tool_settings(tool_name, updated)
        result["arg_string"] = arg_string
        result["effective_settings"] = config.get_tool_settings(tool_name)
        result["self_check"] = self.run_self_check().get(tool_name)
        return result

    def set_nmap_args(self, arg_string: str) -> dict[str, Any]:
        return self.set_tool_arg_string("nmap", arg_string)

    def set_oneforall_args(self, arg_string: str) -> dict[str, Any]:
        return self.set_tool_arg_string("oneforall", arg_string)

    def set_subfinder_args(self, arg_string: str) -> dict[str, Any]:
        return self.set_tool_arg_string("subfinder", arg_string)

    def set_dirsearch_args(self, arg_string: str) -> dict[str, Any]:
        return self.set_tool_arg_string("dirsearch", arg_string)

    def reset_tool_settings(self, tool_name: str) -> dict[str, Any]:
        self._validate_tool(tool_name)
        config.reset_tool_settings(tool_name)
        return {
            "ok": True,
            "tool": tool_name,
            "settings": config.get_tool_settings(tool_name),
        }

    def download_tool(self, tool_name: str) -> dict[str, Any]:
        self._validate_tool(tool_name)
        target = self.targets[tool_name]
        if not target.supports_download():
            return {
                "ok": False,
                "tool": tool_name,
                "message": "当前工具不支持自动下载",
            }

        ok = target.download()
        return {
            "ok": ok,
            "tool": tool_name,
            "info": self.get_tool_info(tool_name),
        }

    def run_self_check(self) -> dict[str, Any]:
        results = ToolSelfChecker().run_all()
        return {
            name: {
                "installed": result.installed,
                "usable": result.usable,
                "path": result.path,
                "version": result.version,
                "message": result.message,
            }
            for name, result in results.items()
        }

    def export_current_config(self) -> dict[str, Any]:
        local_settings = config.load_local_settings()
        return {
            "tool_paths": local_settings.get("tool_paths", {}),
            "tool_settings": local_settings.get("tool_settings", {}),
            "effective_settings": config.get_all_tool_settings(),
        }

    def show_tool_config(self) -> dict[str, Any]:
        return {
            "tools": self.get_all_tools_info(),
            "config": self.export_current_config(),
        }

    @staticmethod
    def save_config_snapshot(output_path: str) -> dict[str, Any]:
        path = Path(output_path)
        snapshot = {
            "tool_paths": config.load_local_settings().get("tool_paths", {}),
            "tool_settings": config.load_local_settings().get("tool_settings", {}),
            "effective_settings": config.get_all_tool_settings(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, snapshot, ensure_ascii=False, indent=2)
        return {"ok": True, "path": str(path.resolve())}

    @staticmethod
    def _validate_tool(tool_name: str):
        if tool_name not in SUPPORTED_TOOLS:
            raise ValueError(f"不支持的工具: {tool_name}")

    @staticmethod
    def parse_arg_string(arg_string: str) -> list[str]:
        text = str(arg_string or "").strip()
        if not text:
            return []
        return shlex.split(text, posix=not sys.platform.startswith("win"))

    @staticmethod
    def _validate_reserved_args(tool_name: str, parsed_args: list[str]):
        reserved = RESERVED_ARG_TOKENS.get(tool_name, set())
        conflicts = [token for token in parsed_args if token in reserved]
        if conflicts:
            raise ValueError(
                f"{tool_name} 参数中包含受包装器管理的保留参数: {', '.join(conflicts)}"
            )

    @staticmethod
    def _sanitize_settings(tool_name: str, values: dict[str, Any]) -> dict[str, Any]:
        defaults = config.DEFAULT_TOOL_SETTINGS.get(tool_name, {})
        sanitized: dict[str, Any] = {}
        for key, value in values.items():
            if key not in defaults:
                raise ValueError(f"{tool_name} 不支持参数: {key}")

            default_value = defaults[key]
            if isinstance(default_value, bool):
                sanitized[key] = bool(value)
            elif isinstance(default_value, int) and not isinstance(default_value, bool):
                sanitized[key] = int(value)
            elif isinstance(default_value, float):
                sanitized[key] = float(value)
            elif isinstance(default_value, list):
                if not isinstance(value, list):
                    raise ValueError(f"{tool_name}.{key} 需要 list")
                sanitized[key] = value
            else:
                sanitized[key] = value
        return sanitized
