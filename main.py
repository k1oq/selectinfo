#!/usr/bin/env python3
"""
Interactive entrypoint for SelectInfo.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from ipaddress import ip_address
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
    enable_reverse_ip: bool = False
    enable_port_scan: bool = False
    port_scan_mode: str | None = None
    enable_web_fingerprint: bool = False
    enable_directory_scan: bool = False
    background: bool = False


def print_banner():
    console.print()
    console.print(
        Panel.fit(
            "[bold blue]SelectInfo[/bold blue] - interactive scanner\n"
            "[dim]Subdomains | Ports | Web fingerprint | Directory scan[/dim]",
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

    table = Table(title="Tool Status", show_header=True)
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Path", overflow="fold")
    table.add_column("Message", overflow="fold")

    for name, result in check_results.items():
        if result.usable:
            status = "[green]usable[/green]"
        elif result.installed:
            status = "[yellow]installed but unusable[/yellow]"
        else:
            status = "[red]missing[/red]"

        table.add_row(
            name,
            status,
            result.version or "-",
            result.path or "-",
            result.message or "-",
        )

    console.print(table)
    console.print("[dim]dirsearch is optional and only used for directory scanning.[/dim]")
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

    console.print(f"[bold yellow]{tool_name} is not ready[/bold yellow]")
    console.print(f"Expected location: {target.get_expected_location()}")
    console.print("  [1] Configure local path")
    if target.supports_download():
        console.print("  [2] Download automatically")
        console.print("  [3] Skip")
        valid_choices = ["1", "2", "3"]
        skip_choice = "3"
    else:
        console.print("  [2] Skip")
        valid_choices = ["1", "2"]
        skip_choice = "2"

    choice = Prompt.ask("Choose an action", choices=valid_choices, default=skip_choice)
    if choice == "1":
        path = Prompt.ask("Tool path").strip()
        if not path:
            console.print("[yellow]No path provided, skipping.[/yellow]")
            return False
        return target.configure_path(path)

    if choice == "2" and target.supports_download():
        console.print(f"[cyan]Downloading {tool_name}...[/cyan]")
        return target.download()

    console.print(f"[yellow]Skipped {tool_name} setup.[/yellow]")
    return False


def ensure_tool_setup(scanner: SubdomainScanner) -> dict[str, bool]:
    tool_status = show_tool_status(scanner)
    missing_required = [name for name in STARTUP_SETUP_TOOLS if not tool_status.get(name)]
    if not missing_required:
        return tool_status

    console.print("[yellow]Some required tools are not ready:[/yellow]")
    console.print(f"  {', '.join(missing_required)}")
    console.print()

    if not Confirm.ask("Configure them now?", default=True):
        return tool_status

    for tool_name in missing_required:
        console.print()
        prompt_tool_setup(scanner, tool_name)

    console.print()
    console.print("[cyan]Refreshing tool status...[/cyan]")
    return show_tool_status(scanner)


def manage_tools_menu():
    api = ToolConfigAPI()

    while True:
        console.print("\n[bold cyan]Tool Config[/bold cyan]")
        console.print("[dim]Tip: you can also edit config/local_settings.json directly.[/dim]")
        console.print("  [1] Show all tools")
        console.print("  [2] Show one tool")
        console.print("  [3] Configure tool path")
        console.print("  [4] Update tool settings")
        console.print("  [5] Reset tool settings")
        console.print("  [6] Download tool")
        console.print("  [0] Back")
        console.print()

        choice = Prompt.ask("Choose", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")
        if choice == "0":
            return

        if choice == "1":
            console.print_json(json.dumps(api.get_all_tools_info(), ensure_ascii=False))
            continue

        tool_name = Prompt.ask("Tool name", choices=api.list_tools())

        if choice == "2":
            console.print_json(json.dumps(api.get_tool_info(tool_name), ensure_ascii=False))
        elif choice == "3":
            path = Prompt.ask("Tool path").strip()
            console.print_json(json.dumps(api.configure_tool_path(tool_name, path), ensure_ascii=False))
        elif choice == "4":
            console.print('Enter JSON settings, for example: {"timeout": 120}')
            raw = Prompt.ask("Settings JSON").strip()
            try:
                values = json.loads(raw)
            except json.JSONDecodeError as exc:
                console.print(f"[red]Invalid JSON: {exc}[/red]")
                continue
            try:
                console.print_json(json.dumps(api.update_tool_settings(tool_name, values), ensure_ascii=False))
            except Exception as exc:
                console.print(f"[red]Update failed: {exc}[/red]")
        elif choice == "5":
            console.print_json(json.dumps(api.reset_tool_settings(tool_name), ensure_ascii=False))
        elif choice == "6":
            console.print_json(json.dumps(api.download_tool(tool_name), ensure_ascii=False))


def prompt_targets_from_lines() -> list[str]:
    console.print("\n[bold]Enter targets (domain/IP), one per line, or input a file path.[/bold]\n")
    first_line = Prompt.ask("").strip()

    targets: list[str] = []
    if first_line and Path(first_line).exists():
        try:
            targets = [
                line.strip()
                for line in Path(first_line).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            console.print(f"[green]Loaded {len(targets)} targets from file.[/green]")
        except Exception as exc:
            console.print(f"[red]Failed to read file: {exc}[/red]")
            return []
    else:
        if first_line:
            targets.append(first_line)
        while True:
            line = Prompt.ask("", default="").strip()
            if not line:
                break
            targets.append(line)

    return targets


def choose_scan_mode() -> str:
    console.print("\n[bold cyan]Port Scan[/bold cyan]\n")
    console.print("[bold]Choose a port preset:[/bold]")

    presets = list(config.PORT_PRESETS.items())
    for index, (_, info) in enumerate(presets, 1):
        console.print(f"  [{index}] {info['name']}")

    console.print()
    choice = Prompt.ask("Choose", default="1")
    try:
        index = int(choice) - 1
        if 0 <= index < len(presets):
            return presets[index][0]
    except ValueError:
        pass
    return "common"


def choose_scan_preset() -> str:
    console.print("\n[bold cyan]Scan Preset[/bold cyan]\n")
    preset_names = config.list_scan_presets()
    for index, preset_name in enumerate(preset_names, 1):
        summary = config.summarize_scan_preset(preset_name)
        default_suffix = " [dim](default)[/dim]" if preset_name == config.SCAN_PRESET_DEFAULT else ""
        console.print(f"  [{index}] {preset_name}{default_suffix}")
        console.print(f"      [dim]{summary}[/dim]")

    console.print()
    choice = Prompt.ask("Choose", default=str(preset_names.index(config.SCAN_PRESET_DEFAULT) + 1))
    try:
        index = int(choice) - 1
        if 0 <= index < len(preset_names):
            return preset_names[index]
    except ValueError:
        pass
    return config.SCAN_PRESET_DEFAULT


def _target_is_ip(target: str) -> bool:
    try:
        ip_address(str(target).strip())
    except ValueError:
        return False
    return True


def _targets_include_ip(targets: list[str]) -> bool:
    return any(_target_is_ip(target) for target in targets)


def build_scan_plan(
    targets: list[str],
    available_tools: list[str],
    tool_status: dict[str, bool],
    *,
    default_enable_port_scan: bool,
    requires_subdomain_tools: bool,
    supports_reverse_ip: bool,
) -> ScanExecutionPlan | None:
    if requires_subdomain_tools:
        preset_name = choose_scan_preset()
        selected_tools = config.resolve_scan_preset_subdomain_tools(
            preset_name,
            available_tools=available_tools,
        )
        parallel = len(selected_tools) > 1
    else:
        preset_name = config.SCAN_PRESET_DEFAULT
        selected_tools = []
        parallel = False

    enable_reverse_ip = False
    enable_port_scan = False
    port_scan_mode = None
    enable_web_fingerprint = False
    enable_directory_scan = False

    if supports_reverse_ip:
        enable_reverse_ip = Confirm.ask("Run reverse-IP enrichment for IP targets?", default=True)

    if tool_status.get("nmap"):
        port_prompt = (
            "Run port scan after subdomain discovery?"
            if requires_subdomain_tools
            else "Run port scan?"
        )
        enable_port_scan = Confirm.ask(port_prompt, default=default_enable_port_scan)
        if enable_port_scan:
            port_scan_mode = choose_scan_mode()
            enable_web_fingerprint = Confirm.ask("Run web fingerprint after port scan?", default=False)
            if enable_web_fingerprint:
                enable_directory_scan = Confirm.ask("Run directory scan after web fingerprint?", default=False)
                if enable_directory_scan and not tool_status.get("dirsearch"):
                    console.print("[yellow]dirsearch is unavailable, directory scan will be skipped.[/yellow]")
    else:
        console.print("[yellow]nmap is unavailable, port/web follow-up stages will be skipped.[/yellow]")

    background = Confirm.ask("Run in background?", default=False)
    plan = ScanExecutionPlan(
        targets=targets,
        tools=selected_tools,
        preset=preset_name,
        skip_wildcard=False,
        skip_validation=False,
        parallel=parallel,
        enable_reverse_ip=enable_reverse_ip,
        enable_port_scan=enable_port_scan,
        port_scan_mode=port_scan_mode,
        enable_web_fingerprint=enable_web_fingerprint,
        enable_directory_scan=enable_directory_scan,
        background=background,
    )

    show_scan_plan(plan, tool_status)
    if not Confirm.ask("Start with this plan?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        return None
    return plan


def show_scan_plan(plan: ScanExecutionPlan, tool_status: dict[str, bool]):
    table = Table(title="Execution Plan", show_header=False)
    table.add_column("Item", style="cyan")
    table.add_column("Config", overflow="fold")

    if len(plan.targets) == 1:
        target_summary = plan.targets[0]
    else:
        preview = ", ".join(plan.targets[:3])
        suffix = f" ... total {len(plan.targets)}" if len(plan.targets) > 3 else ""
        target_summary = preview + suffix

    table.add_row("Targets", target_summary)
    table.add_row("Preset", plan.preset if plan.tools else "N/A for direct IP scan")
    if plan.tools:
        table.add_row("Preset Summary", config.summarize_scan_preset(plan.preset))
    table.add_row("Subdomain Tools", ", ".join(plan.tools) if plan.tools else "Direct IP scan")
    table.add_row("Wildcard Detection", "on")
    table.add_row("DNS Validation", "on")
    table.add_row("Parallel Tools", "on" if plan.parallel else ("off" if plan.tools else "n/a"))
    table.add_row("Reverse IP", "on" if plan.enable_reverse_ip else "off")
    table.add_row("Port Scan", "on" if plan.enable_port_scan else "off")
    if plan.enable_port_scan and plan.port_scan_mode:
        table.add_row("Port Mode", config.PORT_PRESETS[plan.port_scan_mode]["name"])
    table.add_row("Web Fingerprint", "on" if plan.enable_web_fingerprint else "off")
    if plan.enable_directory_scan and not tool_status.get("dirsearch"):
        directory_summary = "on (will be skipped because dirsearch is unavailable)"
    else:
        directory_summary = "on" if plan.enable_directory_scan else "off"
    table.add_row("Directory Scan", directory_summary)
    table.add_row("Background", "on" if plan.background else "off")

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
    if plan.skip_wildcard:
        command.append("--skip-wildcard")
    if plan.skip_validation:
        command.append("--skip-validation")
    if plan.tools and not plan.parallel:
        command.append("--serial")
    if _targets_include_ip(plan.targets):
        command.append("--reverse-ip" if plan.enable_reverse_ip else "--no-reverse-ip")
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
    subdomains = result.get("subdomains") or []
    if not subdomains:
        return

    console.print()
    console.print("[bold]Discovered targets (first 30):[/bold]")

    table = Table(show_header=True)
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP")

    for item in subdomains[:30]:
        table.add_row(item.get("subdomain", "-"), ", ".join(item.get("ip", [])) or "-")

    console.print(table)
    if len(subdomains) > 30:
        console.print(f"[dim]... and {len(subdomains) - 30} more[/dim]")


def scan_single_domain(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    target = Prompt.ask("\n[bold]Enter a target domain or IP[/bold]").strip()
    if not target:
        console.print("[red]Target cannot be empty.[/red]")
        return

    available = get_available_subdomain_tools(scanner, tool_status)
    is_ip_target = scanner.domain_extractor.is_ip_target(target)
    requires_subdomain_tools = not is_ip_target
    if requires_subdomain_tools and not available:
        console.print("[red]No subdomain tools are available. Configure subfinder or oneforall first.[/red]")
        return

    plan = build_scan_plan(
        targets=[target],
        available_tools=available if requires_subdomain_tools else [],
        tool_status=tool_status,
        default_enable_port_scan=bool(tool_status.get("nmap")),
        requires_subdomain_tools=requires_subdomain_tools,
        supports_reverse_ip=is_ip_target,
    )
    if plan is None:
        return

    if plan.background:
        launched = launch_background_plan(plan)
        console.print(f"\n[green]Background job started: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]Status: {launched['status_path']}[/green]")
        console.print(f"[green]Log: {launched['log_path']}[/green]")
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
                enable_reverse_ip=plan.enable_reverse_ip,
                enable_port_scan=plan.enable_port_scan,
                port_mode=plan.port_scan_mode or "common",
                enable_web_fingerprint=plan.enable_web_fingerprint,
                enable_directory_scan=plan.enable_directory_scan,
            )
        show_scan_result(scanner.get_result() or {})
        console.print(f"\n[green]Saved result to: {result['saved_path']}[/green]")
        console.print(f"[green]Saved report to: {result['report_path']}[/green]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")


def scan_batch_domains(scanner: SubdomainScanner, tool_status: dict[str, bool]):
    targets = prompt_targets_from_lines()
    if not targets:
        console.print("[red]No targets provided.[/red]")
        return

    available = get_available_subdomain_tools(scanner, tool_status)
    ip_target_count = sum(1 for item in targets if scanner.domain_extractor.is_ip_target(item))
    requires_subdomain_tools = ip_target_count != len(targets)
    if requires_subdomain_tools and not available:
        console.print("[red]Your batch includes domains, but no subdomain tools are available.[/red]")
        return

    plan = build_scan_plan(
        targets=targets,
        available_tools=available if requires_subdomain_tools else [],
        tool_status=tool_status,
        default_enable_port_scan=False,
        requires_subdomain_tools=requires_subdomain_tools,
        supports_reverse_ip=ip_target_count > 0,
    )
    if plan is None:
        return

    if plan.background:
        launched = launch_background_plan(plan)
        console.print(f"\n[green]Background job started: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]Status: {launched['status_path']}[/green]")
        console.print(f"[green]Log: {launched['log_path']}[/green]")
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
                enable_reverse_ip=plan.enable_reverse_ip,
                enable_port_scan=plan.enable_port_scan,
                port_mode=plan.port_scan_mode or "common",
                enable_web_fingerprint=plan.enable_web_fingerprint,
                enable_directory_scan=plan.enable_directory_scan,
            )
        BatchScanRunner.print_overview(result["batch_summary"], result["summary_path"])
        console.print(f"[green]Saved report to: {result['report_path']}[/green]")
        console.print(f"[dim]Results dir: {config.RESULTS_DIR}[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")


def main():
    print_banner()
    scanner = SubdomainScanner()
    tool_status = ensure_tool_setup(scanner)

    available = get_available_subdomain_tools(scanner, tool_status)
    if not available:
        console.print("[yellow]No subdomain tools are ready. You can still scan direct IP targets.[/yellow]")
        console.print(f"[dim]OneForAll: {config.ONEFORALL_DIR}[/dim]")
        console.print(f"[dim]Subfinder: {config.SUBFINDER_DIR}[/dim]")
        console.print(f"[dim]nmap: {NmapSetupManager.get_expected_location()}[/dim]")
        console.print(f"[dim]dirsearch: {config.DIRSEARCH_DIR}[/dim]")
        console.print()

    console.print("[bold]Choose an action:[/bold]")
    console.print("  [1] Single target scan")
    console.print("  [2] Batch scan")
    console.print("  [3] Tool config")
    console.print()

    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")
    if choice == "1":
        scan_single_domain(scanner, tool_status)
    elif choice == "2":
        scan_batch_domains(scanner, tool_status)
    else:
        manage_tools_menu()

    console.print("\n[cyan]Done[/cyan]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exited.[/yellow]")
        sys.exit(0)
