#!/usr/bin/env python3
"""
Root MCP service entrypoint.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from tools.config_api import ToolConfigAPI


mcp = FastMCP("selectinfo-tools")
api = ToolConfigAPI()


@mcp.tool(description="列出 SelectInfo 支持管理的工具")
def list_tools() -> list[str]:
    return api.list_tools()


@mcp.tool(description="获取所有工具的当前状态、路径和参数")
def get_all_tools_info() -> dict:
    return api.get_all_tools_info()


@mcp.tool(description="获取单个工具的状态、路径和参数")
def get_tool_info(tool_name: str) -> dict:
    return api.get_tool_info(tool_name)


@mcp.tool(description="配置工具路径，例如 subfinder、oneforall、nmap 或 dirsearch")
def configure_tool_path(tool_name: str, path: str) -> dict:
    return api.configure_tool_path(tool_name, path)


@mcp.tool(description="设置工具路径")
def set_tool_path(tool_name: str, path: str) -> dict:
    return api.set_tool_path(tool_name, path)


@mcp.tool(description="更新工具参数，values 为 JSON 对象")
def update_tool_settings(tool_name: str, values: dict) -> dict:
    return api.update_tool_settings(tool_name, values)


@mcp.tool(description="设置 nmap 原始参数字符串，例如 '-sS -Pn'")
def set_nmap_args(arg_string: str) -> dict:
    return api.set_nmap_args(arg_string)


@mcp.tool(description="设置 oneforall 原始参数字符串，例如 '--takeover False'")
def set_oneforall_args(arg_string: str) -> dict:
    return api.set_oneforall_args(arg_string)


@mcp.tool(description="设置 subfinder 原始参数字符串，例如 '-recursive'")
def set_subfinder_args(arg_string: str) -> dict:
    return api.set_subfinder_args(arg_string)


@mcp.tool(description="设置 dirsearch 原始参数字符串，例如 '--exclude-status 404'")
def set_dirsearch_args(arg_string: str) -> dict:
    return api.set_dirsearch_args(arg_string)


@mcp.tool(description="获取当前完整工具配置")
def show_tool_config() -> dict:
    return api.show_tool_config()


@mcp.tool(description="重置某个工具的本地参数覆盖，恢复默认值")
def reset_tool_settings(tool_name: str) -> dict:
    return api.reset_tool_settings(tool_name)


@mcp.tool(description="执行工具自检")
def run_self_check() -> dict:
    return api.run_self_check()


@mcp.tool(description="自动下载支持下载的工具")
def download_tool(tool_name: str) -> dict:
    return api.download_tool(tool_name)


@mcp.tool(description="导出当前配置快照到指定路径")
def export_current_config(output_path: str) -> dict:
    return api.save_config_snapshot(output_path)


if __name__ == "__main__":
    mcp.run()
