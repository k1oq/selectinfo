#!/usr/bin/env python3
"""
Shortcut CLI for tool configuration.
"""

from __future__ import annotations

import argparse
import json
import sys

from tools.config_api import SUPPORTED_TOOLS, ToolConfigAPI


VALUE_OPTIONS = {
    "-nmap",
    "-oneforall",
    "-subfinder",
    "-dirsearch",
    "-nmap-path",
    "-oneforall-path",
    "-subfinder-path",
    "-dirsearch-path",
    "-reset",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SelectInfo 工具快捷配置 CLI")
    parser.add_argument("-show", action="store_true", help="输出当前有效配置和工具状态")
    parser.add_argument("-check", action="store_true", help="执行工具自检")
    parser.add_argument("-reset", choices=SUPPORTED_TOOLS, help="重置指定工具的本地覆盖配置")

    parser.add_argument("-nmap", dest="nmap_args", help='覆盖 nmap 参数，例如 "-sS -Pn"')
    parser.add_argument("-oneforall", dest="oneforall_args", help='覆盖 oneforall extra_args')
    parser.add_argument("-subfinder", dest="subfinder_args", help='覆盖 subfinder extra_args')
    parser.add_argument("-dirsearch", dest="dirsearch_args", help='覆盖 dirsearch extra_args')

    parser.add_argument("-nmap-path", dest="nmap_path", help="设置 nmap 路径")
    parser.add_argument("-oneforall-path", dest="oneforall_path", help="设置 oneforall 路径")
    parser.add_argument("-subfinder-path", dest="subfinder_path", help="设置 subfinder 路径")
    parser.add_argument("-dirsearch-path", dest="dirsearch_path", help="设置 dirsearch 路径")
    return parser


def execute(args: argparse.Namespace) -> dict:
    api = ToolConfigAPI()
    result: dict = {"ok": True, "actions": []}

    if args.reset:
        result["actions"].append(
            {"type": "reset", "tool": args.reset, "result": api.reset_tool_settings(args.reset)}
        )

    path_updates = {
        "nmap": args.nmap_path,
        "oneforall": args.oneforall_path,
        "subfinder": args.subfinder_path,
        "dirsearch": args.dirsearch_path,
    }
    for tool_name, path in path_updates.items():
        if path:
            result["actions"].append(
                {"type": "set_path", "tool": tool_name, "result": api.set_tool_path(tool_name, path)}
            )

    arg_updates = {
        "nmap": args.nmap_args,
        "oneforall": args.oneforall_args,
        "subfinder": args.subfinder_args,
        "dirsearch": args.dirsearch_args,
    }
    for tool_name, arg_string in arg_updates.items():
        if arg_string is not None:
            result["actions"].append(
                {
                    "type": "set_args",
                    "tool": tool_name,
                    "arg_string": arg_string,
                    "result": api.set_tool_arg_string(tool_name, arg_string),
                }
            )

    if args.check:
        result["self_check"] = api.run_self_check()

    if args.show:
        result["show"] = api.show_tool_config()

    if not result["actions"] and not args.check and not args.show:
        raise ValueError("未提供任何操作参数")

    return result


def normalize_argv(argv: list[str]) -> list[str]:
    normalized: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in VALUE_OPTIONS and index + 1 < len(argv):
            normalized.append(f"{token}={argv[index + 1]}")
            index += 2
            continue
        normalized.append(token)
        index += 1
    return normalized


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    try:
        result = execute(parser.parse_args(normalize_argv(sys.argv[1:])))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
