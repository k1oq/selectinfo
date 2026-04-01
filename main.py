#!/usr/bin/env python3
"""
Interactive entrypoint for SelectInfo.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

import config
from core import (
    BatchScanRunner,
    SubdomainScanner,
    run_directory_scan as shared_run_directory_scan,
    run_port_scan as shared_run_port_scan,
    run_web_fingerprint as shared_run_web_fingerprint,
    write_batch_item_reports,
    write_batch_summary_report,
    write_single_scan_report_from_file,
)
from tools import DirsearchTool, NmapSetupManager, ToolConfigAPI, ToolSelfChecker
from utils.logger import console

__version__ = "1.0.0"
STARTUP_SETUP_TOOLS = ("subfinder", "oneforall", "nmap")


@dataclass
class ScanExecutionPlan:
    targets: list[str]
    tools: list[str]
    skip_wildcard: bool = False
    skip_validation: bool = False
    parallel: bool = True
    enable_port_scan: bool = False
    port_scan_mode: str | None = None
    enable_web_fingerprint: bool = False
    enable_directory_scan: bool = False


def print_banner():
    console.print()
    console.print(
        Panel.fit(
            "[bold blue]SelectInfo[/bold blue] - 信息收集工具\n"
            "[dim]子域名收集 | 端口扫描 | Web 指纹识别 | Web 目录扫描[/dim]",
            subtitle=f"v{__version__}",
        )
    )
    console.print()


def get_available_subdomain_tools(scanner: SubdomainScanner, tool_status: dict[str, bool]) -> list[str]:
    return [name for name in scanner.AVAILABLE_TOOLS if tool_status.get(name)]


def show_tool_status(scanner: SubdomainScanner) -> dict[str, bool]:
    checker = ToolSelfChecker()
    check_results = checker.run_all()
    tool_status = {name: result.usable for name, result in check_results.items()}

    table = Table(title="工具状态", show_header=True)
    table.add_column("工具")
    table.add_column("状态")
    table.add_column("版本")
    table.add_column("路径", overflow="fold")
    table.add_column("说明", overflow="fold")

    for name, result in check_results.items():
        if result.usable:
            status = "[green]可用[/green]"
        elif result.installed:
            status = "[yellow]已安装但不可用[/yellow]"
        else:
            status = "[red]未安装[/red]"

        table.add_row(
            name,
            status,
            result.version or "-",
            result.path or "-",
            result.message or "-",
        )

    console.print(table)
    console.print("[dim]提示: dirsearch 是可选工具，仅用于 Web 目录扫描。[/dim]")
    console.print()
    return tool_status


def _get_setup_target(scanner: SubdomainScanner, tool_name: str):
    if tool_name == "nmap":
        return NmapSetupManager
    if tool_name == "dirsearch":
        return DirsearchTool()
    return scanner.tool_manager.get_tool(tool_name)


def prompt_tool_setup(scanner: SubdomainScanner, tool_name: str) -> bool:
    target = _get_setup_target(scanner, tool_name)
    if target is None:
        return False

    console.print(f"[bold yellow]{tool_name} 未就绪[/bold yellow]")
    console.print(f"默认位置: {target.get_expected_location()}")
    console.print("  [1] 输入本地路径")
    if target.supports_download():
        console.print("  [2] 自动下载到默认目录")
        console.print("  [3] 跳过")
        valid_choices = ["1", "2", "3"]
        skip_choice = "3"
    else:
        console.print("  [2] 跳过")
        valid_choices = ["1", "2"]
        skip_choice = "2"

    choice = Prompt.ask("请选择处理方式", choices=valid_choices, default=skip_choice)
    if choice == "1":
        path = Prompt.ask("请输入工具路径").strip()
        if not path:
            console.print("[yellow]未输入路径，跳过[/yellow]")
            return False
        return target.configure_path(path)

    if choice == "2" and target.supports_download():
        console.print(f"[cyan]正在下载 {tool_name}...[/cyan]")
        return target.download()

    console.print(f"[yellow]跳过 {tool_name} 配置[/yellow]")
    return False


def ensure_tool_setup(scanner: SubdomainScanner) -> dict[str, bool]:
    tool_status = show_tool_status(scanner)
    missing_required = [name for name in STARTUP_SETUP_TOOLS if not tool_status.get(name)]
    if not missing_required:
        return tool_status

    console.print("[yellow]检测到以下核心工具未就绪:[/yellow]")
    console.print(f"  {', '.join(missing_required)}")
    console.print()

    if not Confirm.ask("是否现在配置这些工具？", default=True):
        return tool_status

    for tool_name in missing_required:
        console.print()
        prompt_tool_setup(scanner, tool_name)

    console.print()
    console.print("[cyan]工具状态已刷新[/cyan]")
    return show_tool_status(scanner)


def manage_tools_menu():
    api = ToolConfigAPI()

    while True:
        console.print("\n[bold cyan]工具配置[/bold cyan]")
        console.print("[dim]推荐做法: 直接编辑 config/local_settings.json，或运行 python tools/self_check.py[/dim]")
        console.print("  [1] 查看所有工具状态")
        console.print("  [2] 查看单个工具详情")
        console.print("  [3] 配置工具路径")
        console.print("  [4] 修改工具参数")
        console.print("  [5] 重置工具参数")
        console.print("  [6] 自动下载工具")
        console.print("  [0] 返回主菜单")
        console.print()

        choice = Prompt.ask("请选择", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")
        if choice == "0":
            return

        if choice == "1":
            console.print_json(json.dumps(api.get_all_tools_info(), ensure_ascii=False))
            continue

        tool_name = Prompt.ask("请输入工具名", choices=api.list_tools())

        if choice == "2":
            console.print_json(json.dumps(api.get_tool_info(tool_name), ensure_ascii=False))
        elif choice == "3":
            path = Prompt.ask("请输入工具路径").strip()
            console.print_json(json.dumps(api.configure_tool_path(tool_name, path), ensure_ascii=False))
        elif choice == "4":
            console.print('请输入 JSON 参数，例如: {"timeout": 120, "extra_args": ["--exclude-status", "404"]}')
            raw = Prompt.ask("参数 JSON").strip()
            try:
                values = json.loads(raw)
            except json.JSONDecodeError as exc:
                console.print(f"[red]JSON 格式错误: {exc}[/red]")
                continue
            try:
                console.print_json(json.dumps(api.update_tool_settings(tool_name, values), ensure_ascii=False))
            except Exception as exc:
                console.print(f"[red]更新失败: {exc}[/red]")
        elif choice == "5":
            console.print_json(json.dumps(api.reset_tool_settings(tool_name), ensure_ascii=False))
        elif choice == "6":
            console.print_json(json.dumps(api.download_tool(tool_name), ensure_ascii=False))


def prompt_subdomain_tools(available: list[str]) -> list[str]:
    if len(available) == 1:
        console.print(f"[cyan]子域名工具: {available[0]}[/cyan]")
        return list(available)

    console.print("\n[bold cyan]子域名工具[/bold cyan]")
    for index, tool_name in enumerate(available, 1):
        console.print(f"  [{index}] {tool_name}")

    while True:
        raw = Prompt.ask("选择工具编号，逗号分隔，直接回车表示全部", default="").strip()
        if not raw:
            return list(available)

        selected: list[str] = []
        seen = set()
        valid = True
        for token in raw.replace("，", ",").split(","):
            token = token.strip()
            if not token.isdigit():
                valid = False
                break

            index = int(token) - 1
            if not (0 <= index < len(available)):
                valid = False
                break

            tool_name = available[index]
            if tool_name not in seen:
                seen.add(tool_name)
                selected.append(tool_name)

        if valid and selected:
            return selected

        console.print("[red]输入无效，请重新输入。[/red]")


def prompt_targets_from_lines() -> list[str]:
    console.print("\n[bold]请输入域名（每行一个，空行结束），或直接输入文件路径[/bold]\n")
    first_line = Prompt.ask("").strip()

    domains: list[str] = []
    if first_line and Path(first_line).exists():
        try:
            with open(first_line, "r", encoding="utf-8") as file:
                domains = [line.strip() for line in file if line.strip()]
            console.print(f"[green]已从文件加载 {len(domains)} 个域名[/green]")
        except Exception as exc:
            console.print(f"[red]读取文件失败: {exc}[/red]")
            return []
    else:
        if first_line:
            domains.append(first_line)
        while True:
            line = Prompt.ask("", default="").strip()
            if not line:
                break
            domains.append(line)

    return domains


def choose_scan_mode() -> str:
    console.print("\n[bold cyan]端口扫描[/bold cyan]\n")
    console.print("[bold]选择端口范围:[/bold]")

    presets = list(config.PORT_PRESETS.items())
    for index, (_, info) in enumerate(presets, 1):
        console.print(f"  [{index}] {info['name']}")

    console.print()
    choice = Prompt.ask("请选择", default="1")
    try:
        index = int(choice) - 1
        if 0 <= index < len(presets):
            return presets[index][0]
    except ValueError:
        pass
    return "common"


def build_scan_plan(
    targets: list[str],
    available_tools: list[str],
    tool_status: dict[str, bool],
    *,
    default_enable_port_scan: bool,
) -> ScanExecutionPlan | None:
    selected_tools = prompt_subdomain_tools(available_tools)
    run_wildcard = Confirm.ask("是否执行泛解析检测？", default=True)
    run_validation = Confirm.ask("是否执行 DNS 验证？", default=True)
    parallel = len(selected_tools) > 1 and Confirm.ask("是否并行运行子域名工具？", default=True)

    enable_port_scan = False
    port_scan_mode = None
    enable_web_fingerprint = False
    enable_directory_scan = False

    if tool_status.get("nmap"):
        enable_port_scan = Confirm.ask("是否在子域名扫描后执行端口扫描？", default=default_enable_port_scan)
        if enable_port_scan:
            port_scan_mode = choose_scan_mode()
            enable_web_fingerprint = Confirm.ask("是否在端口扫描后执行 Web 指纹识别？", default=False)
            if enable_web_fingerprint:
                enable_directory_scan = Confirm.ask("是否在 Web 指纹后执行 Web 目录扫描？", default=False)
                if enable_directory_scan and not tool_status.get("dirsearch"):
                    console.print("[yellow]dirsearch 当前不可用，目录扫描运行时会被跳过。[/yellow]")
    else:
        console.print("[yellow]nmap 当前不可用，本次将跳过端口扫描、Web 指纹和目录扫描。[/yellow]")

    plan = ScanExecutionPlan(
        targets=targets,
        tools=selected_tools,
        skip_wildcard=not run_wildcard,
        skip_validation=not run_validation,
        parallel=parallel,
        enable_port_scan=enable_port_scan,
        port_scan_mode=port_scan_mode,
        enable_web_fingerprint=enable_web_fingerprint,
        enable_directory_scan=enable_directory_scan,
    )

    show_scan_plan(plan, tool_status)
    if not Confirm.ask("按以上配置开始执行？", default=True):
        console.print("[yellow]已取消[/yellow]")
        return None
    return plan


def show_scan_plan(plan: ScanExecutionPlan, tool_status: dict[str, bool]):
    table = Table(title="执行计划", show_header=False)
    table.add_column("项目", style="cyan")
    table.add_column("配置", overflow="fold")

    if len(plan.targets) == 1:
        target_summary = plan.targets[0]
    else:
        preview = ", ".join(plan.targets[:3])
        suffix = f" ... 共 {len(plan.targets)} 个" if len(plan.targets) > 3 else ""
        target_summary = preview + suffix

    table.add_row("目标", target_summary)
    table.add_row("子域名工具", ", ".join(plan.tools))
    table.add_row("泛解析检测", "是" if not plan.skip_wildcard else "否")
    table.add_row("DNS 验证", "是" if not plan.skip_validation else "否")
    table.add_row("子域名工具并行", "是" if plan.parallel else "否")
    table.add_row("端口扫描", "是" if plan.enable_port_scan else "否")

    if plan.enable_port_scan and plan.port_scan_mode:
        port_mode_name = config.PORT_PRESETS[plan.port_scan_mode]["name"]
        table.add_row("端口范围", port_mode_name)

    table.add_row("Web 指纹识别", "是" if plan.enable_web_fingerprint else "否")

    if plan.enable_directory_scan and not tool_status.get("dirsearch"):
        directory_summary = "是（dirsearch 当前不可用，运行时会跳过）"
    else:
        directory_summary = "是" if plan.enable_directory_scan else "否"
    table.add_row("Web 目录扫描", directory_summary)

    console.print()
    console.print(table)
    console.print()


def scan_single_domain(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[red]没有可用的子域名工具，请先配置 subfinder 或 oneforall。[/red]")
        return

    domain = Prompt.ask("\n[bold]请输入目标域名[/bold]").strip()
    if not domain:
        console.print("[red]域名不能为空[/red]")
        return

    plan = build_scan_plan(
        targets=[domain],
        available_tools=available,
        tool_status=tool_status,
        default_enable_port_scan=bool(tool_status.get("nmap")),
    )
    if plan is None:
        return

    saved_path: Path | None = None
    try:
        result = scanner.scan(
            target=plan.targets[0],
            tools=plan.tools,
            skip_wildcard=plan.skip_wildcard,
            skip_validation=plan.skip_validation,
            parallel=plan.parallel,
        )
        show_scan_result(result)

        saved_path = scanner.save_result()
        console.print(f"\n[green]结果已保存至: {saved_path}[/green]")

        if result.get("wildcard", {}).get("detected"):
            console.print("\n[yellow]检测到泛解析，跳过端口扫描、Web 指纹和目录扫描。[/yellow]")
            return

        if not result.get("subdomains"):
            return

        if not plan.enable_port_scan:
            return

        port_results = run_port_scan(
            result["subdomains"],
            mode=plan.port_scan_mode,
            output_path=saved_path,
        )
        if not port_results:
            return

        if not plan.enable_web_fingerprint:
            return

        fingerprint_result = run_web_fingerprint(
            result["subdomains"],
            port_results,
            output_path=saved_path,
        )
        if not fingerprint_result or not fingerprint_result.get("targets"):
            console.print("[yellow]未识别出可用的 Web 目标，跳过目录扫描。[/yellow]")
            return

        if not plan.enable_directory_scan:
            return

        run_directory_scan(
            fingerprint_result["targets"],
            output_path=saved_path,
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]扫描已取消[/yellow]")
    except Exception as exc:
        console.print(f"[red]扫描出错: {exc}[/red]")


def scan_batch_domains(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[red]没有可用的子域名工具，请先配置 subfinder 或 oneforall。[/red]")
        return

    domains = prompt_targets_from_lines()
    if not domains:
        console.print("[red]没有输入域名[/red]")
        return

    plan = build_scan_plan(
        targets=domains,
        available_tools=available,
        tool_status=tool_status,
        default_enable_port_scan=False,
    )
    if plan is None:
        return

    runner = BatchScanRunner(
        scanner=scanner,
        run_port_scan=run_port_scan,
        run_web_fingerprint=run_web_fingerprint,
        run_directory_scan=run_directory_scan,
    )
    batch_summary, summary_path = runner.run(
        domains=plan.targets,
        tools=plan.tools,
        skip_wildcard=plan.skip_wildcard,
        skip_validation=plan.skip_validation,
        parallel=plan.parallel,
        enable_port_scan=plan.enable_port_scan,
        port_scan_mode=plan.port_scan_mode,
        enable_web_fingerprint=plan.enable_web_fingerprint,
        enable_directory_scan=plan.enable_directory_scan,
    )

    success = batch_summary["statistics"]["success_count"]
    console.print(f"\n[bold green]批量扫描完成: {success}/{len(plan.targets)} 成功[/bold green]")
    runner.print_overview(batch_summary, summary_path)
    console.print(f"[dim]结果保存在: {config.RESULTS_DIR}[/dim]")


def show_scan_result(result: dict):
    if not result.get("subdomains"):
        return

    console.print()
    console.print("[bold]发现的子域名（前 30 个）:[/bold]")

    table = Table(show_header=True)
    table.add_column("子域名", style="cyan")
    table.add_column("IP")

    for item in result["subdomains"][:30]:
        ips = ", ".join(item.get("ip", [])) or "-"
        table.add_row(item["subdomain"], ips)

    console.print(table)
    if len(result["subdomains"]) > 30:
        console.print(f"[dim]... 还有 {len(result['subdomains']) - 30} 个子域名[/dim]")


def merge_result_field(output_path: Path | None, field_name: str, payload: dict):
    if not output_path or not Path(output_path).exists():
        return
    data = load_json_file(output_path)
    data[field_name] = payload
    atomic_write_json(output_path, data, ensure_ascii=False, indent=2)


def run_port_scan(subdomains: list, mode: str | None = None, output_path: Path | None = None) -> Dict:
    hosts = sorted({ip for item in subdomains for ip in item.get("ip", [])})
    if not hosts:
        console.print("[yellow]没有可用的 IP，跳过端口扫描。[/yellow]")
        return {}

    console.print("\n[cyan]端口扫描[/cyan]")
    if mode is None:
        mode = choose_scan_mode()

    try:
        port_scanner = PortScanner()
        results = port_scanner.scan_hosts(hosts, mode=mode)
        if results:
            merge_result_field(output_path, "port_scan", port_scanner.to_port_scan_dict())
            if output_path:
                console.print(f"\n[green]结果已更新至: {output_path}[/green]")
        return results
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]出错: {exc}[/red]")
        return {}


def run_web_fingerprint(
    subdomains: list,
    port_scan_hosts: dict[str, list[int]],
    output_path: Path | None = None,
) -> Dict:
    if not port_scan_hosts:
        console.print("[yellow]没有开放端口结果，跳过 Web 指纹。[/yellow]")
        return {}

    console.print("\n[cyan]Web 指纹识别[/cyan]")
    try:
        scanner = WebFingerprintScanner()
        result = scanner.scan(subdomains, port_scan_hosts)
        if result:
            merge_result_field(output_path, "web_fingerprint", result)
            if output_path:
                console.print(f"\n[green]结果已更新至: {output_path}[/green]")
        return result
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]Web 指纹出错: {exc}[/red]")
        return {}


def run_directory_scan(
    web_targets: list,
    output_path: Path | None = None,
) -> Dict:
    if not web_targets:
        console.print("[yellow]没有可用的 Web 目标，跳过目录扫描。[/yellow]")
        return {}

    console.print("\n[cyan]Web 目录扫描[/cyan]")
    try:
        scanner = DirectoryScanner()
        result = scanner.scan(web_targets)
        if result:
            merge_result_field(output_path, "directory_scan", result)
            if output_path:
                console.print(f"\n[green]结果已更新至: {output_path}[/green]")
        return result
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]目录扫描出错: {exc}[/red]")
        return {}


run_port_scan = shared_run_port_scan
run_web_fingerprint = shared_run_web_fingerprint
run_directory_scan = shared_run_directory_scan


def scan_single_domain(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[red]没有可用的子域名工具，请先配置 subfinder 或 oneforall。[/red]")
        return

    domain = Prompt.ask("\n[bold]请输入目标域名[/bold]").strip()
    if not domain:
        console.print("[red]域名不能为空[/red]")
        return

    plan = build_scan_plan(
        targets=[domain],
        available_tools=available,
        tool_status=tool_status,
        default_enable_port_scan=bool(tool_status.get("nmap")),
    )
    if plan is None:
        return

    saved_path: Path | None = None
    try:
        result = scanner.scan(
            target=plan.targets[0],
            tools=plan.tools,
            skip_wildcard=plan.skip_wildcard,
            skip_validation=plan.skip_validation,
            parallel=plan.parallel,
        )
        show_scan_result(result)

        saved_path = scanner.save_result()
        console.print(f"\n[green]结果已保存至: {saved_path}[/green]")

        if result.get("wildcard", {}).get("detected"):
            console.print("\n[yellow]检测到泛解析，跳过端口扫描、Web 指纹和目录扫描。[/yellow]")
            return

        if not result.get("subdomains"):
            return

        if not plan.enable_port_scan:
            return

        port_results = run_port_scan(
            result["subdomains"],
            mode=plan.port_scan_mode,
            output_path=saved_path,
        )
        if not port_results:
            return

        if not plan.enable_web_fingerprint:
            return

        fingerprint_result = run_web_fingerprint(
            result["subdomains"],
            port_results,
            output_path=saved_path,
        )
        if not fingerprint_result or not fingerprint_result.get("targets"):
            console.print("[yellow]未识别到可用的 Web 目标，跳过目录扫描。[/yellow]")
            return

        if not plan.enable_directory_scan:
            return

        run_directory_scan(
            fingerprint_result["targets"],
            output_path=saved_path,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]扫描已取消[/yellow]")
    except Exception as exc:
        console.print(f"[red]扫描出错: {exc}[/red]")
    finally:
        if saved_path and Path(saved_path).exists():
            report_path = write_single_scan_report_from_file(saved_path)
            console.print(f"[dim]摘要已生成: {report_path}[/dim]")


def scan_batch_domains(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[red]没有可用的子域名工具，请先配置 subfinder 或 oneforall。[/red]")
        return

    domains = prompt_targets_from_lines()
    if not domains:
        console.print("[red]没有输入域名[/red]")
        return

    plan = build_scan_plan(
        targets=domains,
        available_tools=available,
        tool_status=tool_status,
        default_enable_port_scan=False,
    )
    if plan is None:
        return

    runner = BatchScanRunner(
        scanner=scanner,
        run_port_scan=run_port_scan,
        run_web_fingerprint=run_web_fingerprint,
        run_directory_scan=run_directory_scan,
    )
    batch_summary, summary_path = runner.run(
        domains=plan.targets,
        tools=plan.tools,
        skip_wildcard=plan.skip_wildcard,
        skip_validation=plan.skip_validation,
        parallel=plan.parallel,
        enable_port_scan=plan.enable_port_scan,
        port_scan_mode=plan.port_scan_mode,
        enable_web_fingerprint=plan.enable_web_fingerprint,
        enable_directory_scan=plan.enable_directory_scan,
    )

    success = batch_summary["statistics"]["success_count"]
    console.print(f"\n[bold green]批量扫描完成: {success}/{len(plan.targets)} 成功[/bold green]")
    runner.print_overview(batch_summary, summary_path)
    write_batch_item_reports(batch_summary)
    report_path = write_batch_summary_report(batch_summary, summary_path)
    console.print(f"[dim]摘要已生成: {report_path}[/dim]")
    console.print(f"[dim]结果保存在 {config.RESULTS_DIR}[/dim]")


def main():
    print_banner()
    scanner = SubdomainScanner()
    tool_status = ensure_tool_setup(scanner)

    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[red]没有可用的子域名工具[/red]")
        console.print("[yellow]请先配置以下目录中的工具:[/yellow]")
        console.print(f"  - OneForAll: {config.ONEFORALL_DIR}")
        console.print(f"  - Subfinder: {config.SUBFINDER_DIR}")
        console.print(f"  - nmap: {NmapSetupManager.get_expected_location()}")
        console.print(f"  - dirsearch: {config.DIRSEARCH_DIR}")
        return

    console.print("[bold]请选择功能:[/bold]")
    console.print("  [1] 单个域名扫描")
    console.print("  [2] 批量域名扫描")
    console.print("  [3] 工具配置")
    console.print()

    choice = Prompt.ask("请选择", choices=["1", "2", "3"], default="1")
    if choice == "1":
        scan_single_domain(scanner, tool_status)
    elif choice == "2":
        scan_batch_domains(scanner, tool_status)
    else:
        manage_tools_menu()

    console.print("\n[cyan]完成[/cyan]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]已退出[/yellow]")
        sys.exit(0)
