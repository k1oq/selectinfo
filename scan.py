#!/usr/bin/env python3
"""
Non-interactive scan entrypoint for human users.
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

import config
from core import (
    BatchScanRunner,
    SubdomainScanner,
    merge_reverse_ip_into_scan_result,
    persist_reverse_ip_enrichment,
    run_directory_scan,
    run_port_scan,
    run_reverse_ip,
    run_web_fingerprint,
    write_batch_item_reports,
    write_batch_summary_report,
    write_single_scan_report_from_file,
)
from tools.arg_validation import build_tool_settings_override
from tools.dirsearch_wrapper import DirsearchTool
from tools.setup_manager import NmapSetupManager
from utils.background_jobs import (
    create_background_job,
    launch_background_command,
    update_background_job,
)
from utils.logger import console


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SelectInfo CLI for scanning domains or IPs.",
    )
    parser.add_argument("target", nargs="?", help="Single domain or IP target")
    parser.add_argument("--targets-file", help="Batch target file, one domain/IP per line")
    parser.add_argument("--tools", help=argparse.SUPPRESS)
    parser.add_argument(
        "--preset",
        choices=config.list_scan_presets(),
        default=config.SCAN_PRESET_DEFAULT,
        help="Subdomain preset profile. Default: standard",
    )
    parser.add_argument("--subfinder-args", help="Temporary Subfinder argument override")
    parser.add_argument("--oneforall-args", help="Temporary OneForAll argument override")
    parser.add_argument("--skip-wildcard", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--skip-validation", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--serial", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port-scan", action="store_true", help="Enable port scan stage")
    parser.add_argument("--nmap-args", help="Temporary nmap argument override")
    parser.add_argument(
        "--port-mode",
        choices=sorted(config.PORT_PRESETS),
        default="common",
        help="Port scan preset. Default: common",
    )
    parser.add_argument("--web-fingerprint", action="store_true", help="Enable web fingerprint stage")
    parser.add_argument("--directory-scan", action="store_true", help="Enable directory scan stage")
    parser.add_argument(
        "--reverse-ip",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable reverse-IP enrichment for direct IP targets (default: on for IP targets)",
    )
    parser.add_argument("--dirsearch-args", help="Temporary dirsearch argument override")
    parser.add_argument("--results-dir", help="Override default results directory")
    parser.add_argument("--output", help="Explicit JSON output path for single-target mode")
    parser.add_argument("--summary-output", help="Explicit summary report output path")
    parser.add_argument("--background", action="store_true", help="Run in background")
    parser.add_argument("--_background-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_job-id", help=argparse.SUPPRESS)
    parser.add_argument("--_status-file", help=argparse.SUPPRESS)
    parser.add_argument("--_log-file", help=argparse.SUPPRESS)
    return parser


def parse_requested_tools(raw: str | None) -> list[str] | None:
    if raw is None:
        return None

    tools = [token.strip().lower() for token in raw.split(",") if token.strip()]
    if not tools:
        return None

    deduped: list[str] = []
    for tool_name in tools:
        if tool_name not in deduped:
            deduped.append(tool_name)
    return deduped


def parse_cli_tool_overrides(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, dict[str, list[str]]]]:
    raw_overrides: dict[str, str] = {}
    runtime_overrides: dict[str, dict[str, list[str]]] = {}
    option_fields = {
        "subfinder": "subfinder_args",
        "oneforall": "oneforall_args",
        "nmap": "nmap_args",
        "dirsearch": "dirsearch_args",
    }

    for tool_name, field_name in option_fields.items():
        raw_value = str(getattr(args, field_name, "") or "").strip()
        if not raw_value:
            continue

        parsed_args = config.parse_cli_args(raw_value)
        if not parsed_args:
            continue

        raw_overrides[tool_name] = raw_value
        runtime_overrides[tool_name] = build_tool_settings_override(tool_name, parsed_args)

    return raw_overrides, runtime_overrides


def merge_cli_requested_tools(
    requested_tools: list[str] | None,
    cli_tool_overrides: dict[str, str],
    available_tool_names: list[str] | tuple[str, ...],
) -> list[str] | None:
    implied_tools = [name for name in available_tool_names if name in cli_tool_overrides]
    if not requested_tools:
        return implied_tools or None

    merged = list(requested_tools)
    for tool_name in implied_tools:
        if tool_name not in merged:
            merged.append(tool_name)
    return merged


def resolve_requested_tools(
    requested_tools: list[str] | None,
    *,
    preset_name: str,
    cli_tool_overrides: dict[str, str],
    available_tool_names: list[str] | tuple[str, ...],
    available_installed_tools: list[str],
) -> list[str] | None:
    if requested_tools is not None:
        return merge_cli_requested_tools(requested_tools, cli_tool_overrides, available_tool_names)

    implied_tools = [name for name in available_tool_names if name in cli_tool_overrides]
    if implied_tools:
        return implied_tools

    return config.resolve_scan_preset_subdomain_tools(
        preset_name,
        available_tools=available_installed_tools,
    )


def resolve_targets(target: str | None, targets_file: str | None) -> list[str]:
    if target and targets_file:
        raise ValueError("Cannot use both target and --targets-file.")
    if not target and not targets_file:
        raise ValueError("Please provide a domain/IP target or use --targets-file.")

    if targets_file:
        path = Path(targets_file)
        if not path.exists():
            raise ValueError(f"Target file does not exist: {path}")
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    return [str(target).strip()]


def resolve_stage_flags(
    enable_port_scan: bool,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
) -> tuple[bool, bool, bool]:
    if enable_directory_scan:
        enable_web_fingerprint = True
    if enable_web_fingerprint:
        enable_port_scan = True
    return enable_port_scan, enable_web_fingerprint, enable_directory_scan


def select_tools(scanner: SubdomainScanner, requested_tools: list[str] | None) -> tuple[list[str], dict[str, bool]]:
    tool_status = scanner.check_tools()
    available_tools = [name for name in scanner.AVAILABLE_TOOLS if tool_status.get(name)]

    if requested_tools is None:
        if not available_tools:
            raise ValueError("No subdomain tools are available. Configure subfinder or oneforall first.")
        return available_tools, tool_status

    unknown = [name for name in requested_tools if name not in scanner.AVAILABLE_TOOLS]
    if unknown:
        raise ValueError(f"Unknown subdomain tools: {', '.join(unknown)}")

    unavailable = [name for name in requested_tools if not tool_status.get(name)]
    if unavailable:
        raise ValueError(
            "The following subdomain tools are unavailable: "
            + ", ".join(unavailable)
            + ". Please run `python tools/self_check.py` first."
        )

    return requested_tools, tool_status


def validate_followup_tools(
    _tool_status: dict[str, bool],
    *,
    enable_port_scan: bool,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
):
    if (enable_port_scan or enable_web_fingerprint) and not NmapSetupManager.is_available():
        raise ValueError("nmap is unavailable, so port scan and web fingerprint stages cannot run.")
    if enable_directory_scan and not DirsearchTool().check_json_support().get("usable"):
        console.print("[yellow]dirsearch is unavailable, directory scan will be skipped.[/yellow]")


def background_status_context(args: argparse.Namespace) -> dict[str, str]:
    return {
        "job_id": str(getattr(args, "_job_id", "") or "").strip(),
        "status_file": str(getattr(args, "_status_file", "") or "").strip(),
        "log_file": str(getattr(args, "_log_file", "") or "").strip(),
    }


def update_background_scan_status(args: argparse.Namespace, **fields: Any):
    context = background_status_context(args)
    if not context["status_file"]:
        return

    payload = dict(fields)
    if context["job_id"]:
        payload.setdefault("job_id", context["job_id"])
    if context["log_file"]:
        payload.setdefault("log_path", context["log_file"])
    update_background_job(context["status_file"], **payload)


def launch_background_scan(argv: list[str]) -> dict[str, Any]:
    job = create_background_job(prefix="scan", metadata={"entrypoint": "scan.py"})
    child_argv = [arg for arg in argv if arg != "--background"]
    child_argv.extend(
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

    command = [sys.executable, str(Path(__file__).resolve()), *child_argv]
    return launch_background_command(command, job, cwd=Path(__file__).parent)


@contextmanager
def overridden_results_dir(results_dir: str | None):
    if not results_dir:
        yield Path(config.RESULTS_DIR)
        return

    original = config.RESULTS_DIR
    config.RESULTS_DIR = Path(results_dir).expanduser().resolve()
    try:
        config.ensure_dirs()
        yield Path(config.RESULTS_DIR)
    finally:
        config.RESULTS_DIR = original


def run_single_scan(
    scanner: SubdomainScanner,
    *,
    target: str,
    tools: list[str],
    scan_preset: str = config.SCAN_PRESET_DEFAULT,
    skip_wildcard: bool,
    skip_validation: bool,
    parallel: bool,
    enable_reverse_ip: bool,
    enable_port_scan: bool,
    port_mode: str,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
    output_path: str | None = None,
    summary_output: str | None = None,
) -> dict[str, Path]:
    result = scanner.scan(
        target=target,
        tools=tools,
        skip_wildcard=skip_wildcard,
        skip_validation=skip_validation,
        parallel=parallel,
    )
    result["scan_preset"] = scan_preset

    saved_path = scanner.save_result(output_path=Path(output_path) if output_path else None)
    port_results: dict[str, list[int]] = {}

    if not result.get("wildcard", {}).get("detected") and result.get("subdomains") and enable_port_scan:
        port_results = run_port_scan(
            result["subdomains"],
            mode=port_mode,
            output_path=saved_path,
        )

    if enable_reverse_ip and result.get("target_type") == "ip":
        target_ip = str(result.get("target", "") or "")
        reverse_result = run_reverse_ip(
            target_ip,
            open_ports=sorted(port_results.get(target_ip, [])) if port_results else None,
            output_path=saved_path,
        )
        merge_reverse_ip_into_scan_result(result, reverse_result)
        persist_reverse_ip_enrichment(saved_path, result)

    if port_results and enable_web_fingerprint:
        fingerprint_result = run_web_fingerprint(
            result["subdomains"],
            port_results,
            output_path=saved_path,
        )
        if fingerprint_result and fingerprint_result.get("targets") and enable_directory_scan:
            run_directory_scan(
                fingerprint_result["targets"],
                output_path=saved_path,
            )

    report_path = write_single_scan_report_from_file(saved_path, output_path=summary_output)
    return {
        "saved_path": Path(saved_path),
        "report_path": Path(report_path),
    }


def run_batch_scan(
    scanner: SubdomainScanner,
    *,
    targets: list[str],
    tools: list[str],
    scan_preset: str = config.SCAN_PRESET_DEFAULT,
    skip_wildcard: bool,
    skip_validation: bool,
    parallel: bool,
    enable_reverse_ip: bool,
    enable_port_scan: bool,
    port_mode: str,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
    summary_output: str | None = None,
) -> dict[str, Any]:
    runner = BatchScanRunner(
        scanner=scanner,
        run_port_scan=run_port_scan,
        run_reverse_ip=run_reverse_ip,
        run_web_fingerprint=run_web_fingerprint,
        run_directory_scan=run_directory_scan,
    )
    batch_summary, summary_path = runner.run(
        domains=targets,
        tools=tools,
        scan_preset=scan_preset,
        skip_wildcard=skip_wildcard,
        skip_validation=skip_validation,
        parallel=parallel,
        enable_reverse_ip=enable_reverse_ip,
        enable_port_scan=enable_port_scan,
        port_scan_mode=port_mode,
        enable_web_fingerprint=enable_web_fingerprint,
        enable_directory_scan=enable_directory_scan,
    )
    item_report_paths = write_batch_item_reports(batch_summary)
    batch_report_path = write_batch_summary_report(
        batch_summary,
        summary_path,
        output_path=summary_output,
    )
    return {
        "batch_summary": batch_summary,
        "summary_path": Path(summary_path),
        "report_path": Path(batch_report_path),
        "item_report_paths": item_report_paths,
    }


def _resolve_ip_only_target_tools(
    scanner: SubdomainScanner,
    requested_tools: list[str] | None,
) -> tuple[list[str], dict[str, bool]]:
    tool_status = scanner.check_tools()
    if requested_tools:
        unknown = [name for name in requested_tools if name not in scanner.AVAILABLE_TOOLS]
        if unknown:
            raise ValueError(f"Unknown subdomain tools: {', '.join(unknown)}")
    return [], tool_status


def _target_is_ip(scanner: SubdomainScanner, target: str) -> bool:
    result = scanner.domain_extractor.is_ip_target(target)
    return result if isinstance(result, bool) else False


def print_plan(
    targets: list[str],
    tools: list[str],
    *,
    preset_name: str,
    skip_wildcard: bool,
    skip_validation: bool,
    parallel: bool,
    enable_reverse_ip: bool,
    enable_port_scan: bool,
    port_mode: str,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
    preset_summary: str | None = None,
    tool_arg_overrides: dict[str, str] | None = None,
    background: bool = False,
):
    table = Table(title="Execution Plan", show_header=False)
    table.add_column("Item", style="cyan")
    table.add_column("Config", overflow="fold")

    if len(targets) == 1:
        target_summary = targets[0]
    else:
        preview = ", ".join(targets[:3])
        suffix = f" ... total {len(targets)}" if len(targets) > 3 else ""
        target_summary = preview + suffix

    table.add_row("Targets", target_summary)
    table.add_row("Preset", preset_name if tools else "N/A for direct IP scan")
    if preset_summary and tools:
        table.add_row("Preset Summary", preset_summary)
    table.add_row("Subdomain Tools", ", ".join(tools) if tools else "Direct IP scan")
    if tool_arg_overrides:
        ordered_names = ("subfinder", "oneforall", "nmap", "dirsearch")
        display = " ; ".join(
            f"{name}: {tool_arg_overrides[name]}"
            for name in ordered_names
            if name in tool_arg_overrides
        )
        table.add_row("Overrides", display)
    table.add_row("Wildcard Detection", "off" if skip_wildcard else "on")
    table.add_row("DNS Validation", "off" if skip_validation else "on")
    table.add_row("Parallel Tools", "on" if tools and parallel else ("off" if tools else "n/a"))
    table.add_row("Reverse IP", "on" if enable_reverse_ip else "off")
    table.add_row("Port Scan", "on" if enable_port_scan else "off")
    if enable_port_scan:
        table.add_row("Port Mode", config.PORT_PRESETS[port_mode]["name"])
    table.add_row("Web Fingerprint", "on" if enable_web_fingerprint else "off")
    table.add_row("Directory Scan", "on" if enable_directory_scan else "off")
    table.add_row("Background", "on" if background else "off")
    console.print()
    console.print(table)
    console.print()


def execute(args: argparse.Namespace) -> dict[str, Any]:
    targets = resolve_targets(getattr(args, "target", None), getattr(args, "targets_file", None))
    if len(targets) > 1 and getattr(args, "output", None):
        raise ValueError("--output only supports single-target mode. Use --results-dir for batch mode.")

    preset_name = config.normalize_scan_preset_name(getattr(args, "preset", None))
    preset_runtime_tool_overrides = config.get_scan_preset_overrides(preset_name)
    cli_tool_arg_overrides, cli_runtime_tool_overrides = parse_cli_tool_overrides(args)
    runtime_tool_overrides = config.merge_tool_setting_layers(
        preset_runtime_tool_overrides,
        cli_runtime_tool_overrides,
    )
    requested_tools = parse_requested_tools(getattr(args, "tools", None))
    enable_port_scan, enable_web_fingerprint, enable_directory_scan = resolve_stage_flags(
        bool(getattr(args, "port_scan", False) or ("nmap" in cli_tool_arg_overrides)),
        bool(getattr(args, "web_fingerprint", False)),
        bool(getattr(args, "directory_scan", False) or ("dirsearch" in cli_tool_arg_overrides)),
    )
    if getattr(args, "skip_validation", False) and enable_directory_scan:
        raise ValueError("Directory scan requires DNS validation and cannot be used with --skip-validation.")

    with config.override_tool_settings(runtime_tool_overrides):
        scanner = SubdomainScanner()
        has_domain_targets = any(not _target_is_ip(scanner, target) for target in targets)
        has_ip_targets = any(_target_is_ip(scanner, target) for target in targets)
        explicit_reverse_ip = getattr(args, "reverse_ip", None)
        if explicit_reverse_ip is None:
            enable_reverse_ip = has_ip_targets
        else:
            enable_reverse_ip = bool(explicit_reverse_ip and has_ip_targets)

        if has_domain_targets:
            tool_status = scanner.check_tools()
            available_installed_tools = [
                name for name in scanner.AVAILABLE_TOOLS if tool_status.get(name)
            ]
            requested_tools = resolve_requested_tools(
                requested_tools,
                preset_name=preset_name,
                cli_tool_overrides=cli_tool_arg_overrides,
                available_tool_names=tuple(scanner.AVAILABLE_TOOLS),
                available_installed_tools=available_installed_tools,
            )
            tools, tool_status = select_tools(scanner, requested_tools)
        else:
            tools, tool_status = _resolve_ip_only_target_tools(scanner, requested_tools)

        validate_followup_tools(
            tool_status,
            enable_port_scan=enable_port_scan,
            enable_web_fingerprint=enable_web_fingerprint,
            enable_directory_scan=enable_directory_scan,
        )

        print_plan(
            targets,
            tools,
            preset_name=preset_name,
            skip_wildcard=bool(getattr(args, "skip_wildcard", False)),
            skip_validation=bool(getattr(args, "skip_validation", False)),
            parallel=not bool(getattr(args, "serial", False)),
            enable_reverse_ip=enable_reverse_ip,
            enable_port_scan=enable_port_scan,
            port_mode=str(getattr(args, "port_mode", "common")),
            enable_web_fingerprint=enable_web_fingerprint,
            enable_directory_scan=enable_directory_scan,
            preset_summary=config.summarize_scan_preset(preset_name),
            tool_arg_overrides=cli_tool_arg_overrides,
            background=bool(getattr(args, "background", False) or getattr(args, "_background_child", False)),
        )

        with overridden_results_dir(getattr(args, "results_dir", None)):
            if len(targets) == 1:
                return run_single_scan(
                    scanner,
                    target=targets[0],
                    tools=tools,
                    scan_preset=preset_name,
                    skip_wildcard=bool(getattr(args, "skip_wildcard", False)),
                    skip_validation=bool(getattr(args, "skip_validation", False)),
                    parallel=not bool(getattr(args, "serial", False)),
                    enable_reverse_ip=enable_reverse_ip,
                    enable_port_scan=enable_port_scan,
                    port_mode=str(getattr(args, "port_mode", "common")),
                    enable_web_fingerprint=enable_web_fingerprint,
                    enable_directory_scan=enable_directory_scan,
                    output_path=getattr(args, "output", None),
                    summary_output=getattr(args, "summary_output", None),
                )

            return run_batch_scan(
                scanner,
                targets=targets,
                tools=tools,
                scan_preset=preset_name,
                skip_wildcard=bool(getattr(args, "skip_wildcard", False)),
                skip_validation=bool(getattr(args, "skip_validation", False)),
                parallel=not bool(getattr(args, "serial", False)),
                enable_reverse_ip=enable_reverse_ip,
                enable_port_scan=enable_port_scan,
                port_mode=str(getattr(args, "port_mode", "common")),
                enable_web_fingerprint=enable_web_fingerprint,
                enable_directory_scan=enable_directory_scan,
                summary_output=getattr(args, "summary_output", None),
            )


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else list(sys.argv[1:])
    parser = build_parser()
    parsed = parser.parse_args(argv)

    if parsed.background and not parsed._background_child:
        try:
            launched = launch_background_scan(argv)
        except Exception as exc:
            console.print(f"[red]Failed to start background scan: {exc}[/red]")
            return 1

        console.print(f"[green]Background job started: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]Status: {launched['status_path']}[/green]")
        console.print(f"[green]Log: {launched['log_path']}[/green]")
        return 0

    if parsed._background_child:
        update_background_scan_status(
            parsed,
            status="running",
            pid=os.getpid(),
            child_started_at=datetime.now().isoformat(),
        )

    try:
        result = execute(parsed)
    except KeyboardInterrupt:
        update_background_scan_status(
            parsed,
            status="cancelled",
            finished_at=datetime.now().isoformat(),
            exit_code=1,
        )
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        return 1
    except Exception as exc:
        update_background_scan_status(
            parsed,
            status="failed",
            finished_at=datetime.now().isoformat(),
            exit_code=1,
            error=str(exc),
        )
        console.print(f"[red]Failed to start scan: {exc}[/red]")
        return 1

    if "saved_path" in result:
        status_result = {
            "saved_path": str(result["saved_path"]),
            "report_path": str(result["report_path"]),
        }
    else:
        status_result = {
            "summary_path": str(result["summary_path"]),
            "report_path": str(result["report_path"]),
        }

    update_background_scan_status(
        parsed,
        status="completed",
        finished_at=datetime.now().isoformat(),
        exit_code=0,
        result=status_result,
    )

    if "saved_path" in result:
        console.print(f"[green]Result file: {result['saved_path']}[/green]")
        console.print(f"[green]Report file: {result['report_path']}[/green]")
    else:
        stats = result["batch_summary"]["statistics"]
        console.print(f"[green]Batch scan finished: {stats['success_count']}/{stats['total_domains']} succeeded[/green]")
        console.print(f"[green]Summary file: {result['summary_path']}[/green]")
        console.print(f"[green]Report file: {result['report_path']}[/green]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
