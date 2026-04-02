#!/usr/bin/env python3
"""
Interactive entrypoint for SelectInfo.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

import config
import scan as cli_scan
from core import BatchScanRunner, SubdomainScanner
from tools import DirsearchTool, NmapSetupManager, ToolConfigAPI, ToolSelfChecker
from utils.background_jobs import create_background_job, launch_background_command
from utils.logger import console

__version__ = "1.0.0"
STARTUP_SETUP_TOOLS = ("subfinder", "oneforall", "nmap")


@dataclass
class ScanExecutionPlan:
    targets: list[str]
    tools: list[str]
    preset: str = config.SCAN_PRESET_DEFAULT
    skip_wildcard: bool = False
    skip_validation: bool = False
    parallel: bool = True
    enable_port_scan: bool = False
    port_scan_mode: str | None = None
    enable_web_fingerprint: bool = False
    enable_directory_scan: bool = False
    background: bool = False


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


def show_tool_status(_scanner: SubdomainScanner) -> dict[str, bool]:
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


def prompt_targets_from_lines() -> list[str]:
    console.print("\n[bold]请输入域名（每行一个，空行结束），或直接输入文件路径[/bold]\n")
    first_line = Prompt.ask("").strip()

    domains: list[str] = []
    if first_line and Path(first_line).exists():
        try:
            domains = [
                line.strip()
                for line in Path(first_line).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
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


def choose_scan_preset() -> str:
    console.print("\n[bold cyan]扫描档位[/bold cyan]\n")
    preset_names = config.list_scan_presets()
    for index, preset_name in enumerate(preset_names, 1):
        summary = config.summarize_scan_preset(preset_name)
        default_suffix = " [dim](默认)[/dim]" if preset_name == config.SCAN_PRESET_DEFAULT else ""
        console.print(f"  [{index}] {preset_name}{default_suffix}")
        console.print(f"      [dim]{summary}[/dim]")

    console.print()
    choice = Prompt.ask("请选择", default=str(preset_names.index(config.SCAN_PRESET_DEFAULT) + 1))
    try:
        index = int(choice) - 1
        if 0 <= index < len(preset_names):
            return preset_names[index]
    except ValueError:
        pass
    return config.SCAN_PRESET_DEFAULT


def build_scan_plan(
    targets: list[str],
    available_tools: list[str],
    tool_status: dict[str, bool],
    *,
    default_enable_port_scan: bool,
) -> ScanExecutionPlan | None:
    preset_name = choose_scan_preset()
    selected_tools = config.resolve_scan_preset_subdomain_tools(
        preset_name,
        available_tools=available_tools,
    )
    parallel = len(selected_tools) > 1

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

    background = Confirm.ask("是否后台运行？日志和状态会写入 runtime/jobs", default=False)
    plan = ScanExecutionPlan(
        targets=targets,
        tools=selected_tools,
        preset=preset_name,
        skip_wildcard=False,
        skip_validation=False,
        parallel=parallel,
        enable_port_scan=enable_port_scan,
        port_scan_mode=port_scan_mode,
        enable_web_fingerprint=enable_web_fingerprint,
        enable_directory_scan=enable_directory_scan,
        background=background,
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
    table.add_row("参数档位", plan.preset)
    table.add_row("档位摘要", config.summarize_scan_preset(plan.preset))
    table.add_row("子域名工具", ", ".join(plan.tools))
    table.add_row("泛解析检测", "默认开启")
    table.add_row("DNS 存活验证", "默认开启")
    table.add_row("子域名工具并行", "自动并行" if plan.parallel else "单工具串行")
    table.add_row("端口扫描", "是" if plan.enable_port_scan else "否")
    if plan.enable_port_scan and plan.port_scan_mode:
        table.add_row("端口范围", config.PORT_PRESETS[plan.port_scan_mode]["name"])
    table.add_row("Web 指纹识别", "是" if plan.enable_web_fingerprint else "否")

    if plan.enable_directory_scan and not tool_status.get("dirsearch"):
        directory_summary = "是（dirsearch 当前不可用，运行时会跳过）"
    else:
        directory_summary = "是" if plan.enable_directory_scan else "否"
    table.add_row("Web 目录扫描", directory_summary)
    table.add_row("后台运行", "是" if plan.background else "否")

    console.print()
    console.print(table)
    console.print()


def _build_background_scan_command(plan: ScanExecutionPlan, job: dict[str, object]) -> list[str]:
    command = [sys.executable, str((Path(__file__).parent / "scan.py").resolve())]

    if len(plan.targets) == 1:
        command.append(plan.targets[0])
    else:
        targets_file = Path(job["job_dir"]) / "targets.txt"
        targets_file.write_text("\n".join(plan.targets) + "\n", encoding="utf-8")
        command.extend(["--targets-file", str(targets_file)])

    command.extend(["--preset", plan.preset])
    if plan.enable_port_scan:
        command.append("--port-scan")
    if plan.port_scan_mode:
        command.extend(["--port-mode", str(plan.port_scan_mode)])
    if plan.enable_web_fingerprint:
        command.append("--web-fingerprint")
    if plan.enable_directory_scan:
        command.append("--directory-scan")

    command.extend(
        [
            "--_background-child",
            "--_job-id",
            str(job["job_id"]),
            "--_status-file",
            str(job["status_path"]),
            "--_log-file",
            str(job["log_path"]),
        ]
    )
    return command


def launch_background_plan(plan: ScanExecutionPlan) -> dict[str, object]:
    job = create_background_job(prefix="scan", metadata={"entrypoint": "main.py"})
    command = _build_background_scan_command(plan, job)
    return launch_background_command(command, job, cwd=Path(__file__).parent)


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

    if plan.background:
        launched = launch_background_plan(plan)
        console.print(f"\n[green]后台任务已启动: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]状态文件: {launched['status_path']}[/green]")
        console.print(f"[green]日志文件: {launched['log_path']}[/green]")
        return

    try:
        with config.override_tool_settings(config.get_scan_preset_overrides(plan.preset)):
            result = cli_scan.run_single_scan(
                scanner,
                target=plan.targets[0],
                tools=plan.tools,
                scan_preset=plan.preset,
                skip_wildcard=plan.skip_wildcard,
                skip_validation=plan.skip_validation,
                parallel=plan.parallel,
                enable_port_scan=plan.enable_port_scan,
                port_mode=plan.port_scan_mode or "common",
                enable_web_fingerprint=plan.enable_web_fingerprint,
                enable_directory_scan=plan.enable_directory_scan,
            )
        show_scan_result(scanner.get_result() or {})
        console.print(f"\n[green]结果已保存至: {result['saved_path']}[/green]")
        console.print(f"[green]摘要已生成: {result['report_path']}[/green]")
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

    if plan.background:
        launched = launch_background_plan(plan)
        console.print(f"\n[green]后台任务已启动: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]状态文件: {launched['status_path']}[/green]")
        console.print(f"[green]日志文件: {launched['log_path']}[/green]")
        return

    try:
        with config.override_tool_settings(config.get_scan_preset_overrides(plan.preset)):
            result = cli_scan.run_batch_scan(
                scanner,
                targets=plan.targets,
                tools=plan.tools,
                scan_preset=plan.preset,
                skip_wildcard=plan.skip_wildcard,
                skip_validation=plan.skip_validation,
                parallel=plan.parallel,
                enable_port_scan=plan.enable_port_scan,
                port_mode=plan.port_scan_mode or "common",
                enable_web_fingerprint=plan.enable_web_fingerprint,
                enable_directory_scan=plan.enable_directory_scan,
            )
        BatchScanRunner.print_overview(result["batch_summary"], result["summary_path"])
        console.print(f"[green]摘要已生成: {result['report_path']}[/green]")
        console.print(f"[dim]结果保存在: {config.RESULTS_DIR}[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]扫描已取消[/yellow]")
    except Exception as exc:
        console.print(f"[red]扫描出错: {exc}[/red]")


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
