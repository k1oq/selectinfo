"""
Shared tool argument parsing rules for CLI and configuration APIs.
"""

from __future__ import annotations

SUPPORTED_TOOLS = ("subfinder", "oneforall", "nmap", "dirsearch")

TOOL_ARG_SETTING_KEYS = {
    "subfinder": "extra_args",
    "oneforall": "extra_args",
    "nmap": "args",
    "dirsearch": "extra_args",
}

RESERVED_ARG_TOKENS = {
    "subfinder": {"-d", "-domain", "-silent", "-all", "-config", "-pc"},
    "oneforall": {"--target", "--alive", "--brute", "--fmt", "--path", "run"},
    "nmap": {"-p", "-oA", "-oG", "-oN", "-oS", "-oX", "-iL"},
    "dirsearch": {"-u", "--url", "--format", "-o", "--output", "-t", "--threads"},
}


def get_tool_arg_setting_key(tool_name: str) -> str:
    if tool_name not in TOOL_ARG_SETTING_KEYS:
        raise ValueError(f"不支持的工具: {tool_name}")
    return TOOL_ARG_SETTING_KEYS[tool_name]


def validate_tool_arg_tokens(tool_name: str, parsed_args: list[str]):
    get_tool_arg_setting_key(tool_name)
    reserved = RESERVED_ARG_TOKENS.get(tool_name, set())
    conflicts = [token for token in parsed_args if token in reserved]
    if conflicts:
        raise ValueError(
            f"{tool_name} 参数中包含受包装器管理的保留参数: {', '.join(conflicts)}"
        )


def build_tool_settings_override(tool_name: str, parsed_args: list[str]) -> dict[str, list[str]]:
    validate_tool_arg_tokens(tool_name, parsed_args)
    return {get_tool_arg_setting_key(tool_name): list(parsed_args)}
