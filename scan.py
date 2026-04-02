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
    run_directory_scan,
    run_port_scan,
    run_web_fingerprint,
    write_batch_item_reports,
    write_batch_summary_report,
    write_single_scan_report_from_file,
)
from utils.background_jobs import (
    create_background_job,
    launch_background_command,
    update_background_job,
)
from tools.arg_validation import build_tool_settings_override
from tools.dirsearch_wrapper import DirsearchTool
from tools.setup_manager import NmapSetupManager
from utils.logger import console


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SelectInfo 非交互扫描入口，适合直接运行单域名或批量任务。",
    )
    parser.add_argument("target", nargs="?", help="单个目标域名")
    parser.add_argument("--targets-file", help="批量目标文件，每行一个域名")
    parser.add_argument(
        "--tools",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--preset",
        choices=config.list_scan_presets(),
        default=config.SCAN_PRESET_DEFAULT,
        help="扫描参数预设档位，默认 standard",
    )
    parser.add_argument("--subfinder-args", help="本次运行临时覆盖 Subfinder 参数字符串")
    parser.add_argument("--oneforall-args", help="本次运行临时覆盖 OneForAll 参数字符串")
    parser.add_argument("--skip-wildcard", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--skip-validation", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--serial", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument("--port-scan", action="store_true", help="启用端口扫描")
    parser.add_argument("--nmap-args", help="本次运行临时覆盖端口扫描阶段的 nmap 参数字符串")
    parser.add_argument(
        "--port-mode",
        choices=sorted(config.PORT_PRESETS),
        default="common",
        help="端口扫描预设，默认 common",
    )
    parser.add_argument("--web-fingerprint", action="store_true", help="启用 Web 指纹识别")
    parser.add_argument("--directory-scan", action="store_true", help="启用 Web 目录扫描")
    parser.add_argument("--dirsearch-args", help="本次运行临时覆盖 dirsearch 参数字符串")

    parser.add_argument("--results-dir", help="覆盖默认 results 目录")
    parser.add_argument("--output", help="单目标模式下显式指定 JSON 结果路径")
    parser.add_argument("--summary-output", help="显式指定摘要报告路径（统一输出 .xlsx）")
    parser.add_argument("--background", action="store_true", help="后台运行，并将日志写入 runtime/jobs")

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
        raise ValueError("不能同时指定单个 target 和 --targets-file。")
    if not target and not targets_file:
        raise ValueError("请提供目标域名，或使用 --targets-file。")

    if targets_file:
        path = Path(targets_file)
        if not path.exists():
            raise ValueError(f"目标文件不存在: {path}")
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
            raise ValueError("没有可用的子域名工具，请先配置 subfinder 或 oneforall。")
        return available_tools, tool_status

    unknown = [name for name in requested_tools if name not in scanner.AVAILABLE_TOOLS]
    if unknown:
        raise ValueError(f"未知的子域名工具: {', '.join(unknown)}")

    unavailable = [name for name in requested_tools if not tool_status.get(name)]
    if unavailable:
        raise ValueError(
            "以下子域名工具当前不可用: "
            + ", ".join(unavailable)
            + "。请先运行 `python tools/self_check.py` 检查环境。"
        )

    return requested_tools, tool_status


def validate_followup_tools(
    _tool_status: dict[str, bool],
    *,
    enable_port_scan: bool,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
):
    # `select_tools()` 只返回子域名工具状态；后续阶段工具需在这里独立检测。
    if (enable_port_scan or enable_web_fingerprint) and not NmapSetupManager.is_available():
        raise ValueError("当前 nmap 不可用，无法执行端口扫描或 Web 指纹识别。请先运行 `python tools/self_check.py`。")
    if enable_directory_scan and not DirsearchTool().check_json_support().get("usable"):
        console.print("[yellow]dirsearch 当前不可用，目录扫描阶段会被自动跳过。[/yellow]")


def print_plan(
    targets: list[str],
    tools: list[str],
    *,
    preset_name: str,
    skip_wildcard: bool,
    skip_validation: bool,
    parallel: bool,
    enable_port_scan: bool,
    port_mode: str,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
    preset_summary: str | None = None,
    tool_arg_overrides: dict[str, str] | None = None,
    background: bool = False,
):
    table = Table(title="执行计划", show_header=False)
    table.add_column("项目", style="cyan")
    table.add_column("配置", overflow="fold")

    if len(targets) == 1:
        target_summary = targets[0]
    else:
        preview = ", ".join(targets[:3])
        suffix = f" ... 共 {len(targets)} 个" if len(targets) > 3 else ""
        target_summary = preview + suffix

    table.add_row("目标", target_summary)
    table.add_row("参数档位", preset_name)
    if preset_summary:
        table.add_row("档位摘要", preset_summary)
    table.add_row("子域名工具", ", ".join(tools))
    if tool_arg_overrides:
        ordered_names = ("subfinder", "oneforall", "nmap", "dirsearch")
        display = " ; ".join(
            f"{name}: {tool_arg_overrides[name]}"
            for name in ordered_names
            if name in tool_arg_overrides
        )
        table.add_row("临时参数覆盖", display)
    table.add_row("泛解析检测", "否" if skip_wildcard else "是")
    table.add_row("DNS 存活验证", "否" if skip_validation else "是")
    table.add_row("工具并行", "是" if parallel else "否")
    table.add_row("端口扫描", "是" if enable_port_scan else "否")
    if enable_port_scan:
        table.add_row("端口预设", config.PORT_PRESETS[port_mode]["name"])
    table.add_row("Web 指纹", "是" if enable_web_fingerprint else "否")
    table.add_row("目录扫描", "是" if enable_directory_scan else "否")
    table.add_row("后台运行", "是" if background else "否")
    console.print()
    console.print(table)
    console.print()


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

    if not result.get("wildcard", {}).get("detected") and result.get("subdomains") and enable_port_scan:
        port_results = run_port_scan(
            result["subdomains"],
            mode=port_mode,
            output_path=saved_path,
        )
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
    enable_port_scan: bool,
    port_mode: str,
    enable_web_fingerprint: bool,
    enable_directory_scan: bool,
    summary_output: str | None = None,
) -> dict[str, Any]:
    runner = BatchScanRunner(
        scanner=scanner,
        run_port_scan=run_port_scan,
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


def execute(args: argparse.Namespace) -> dict[str, Any]:
    targets = resolve_targets(args.target, args.targets_file)
    if len(targets) > 1 and args.output:
        raise ValueError("--output 仅支持单目标模式，请在批量模式下使用 --results-dir。")

    preset_name = config.normalize_scan_preset_name(getattr(args, "preset", None))
    preset_runtime_tool_overrides = config.get_scan_preset_overrides(preset_name)
    cli_tool_arg_overrides, cli_runtime_tool_overrides = parse_cli_tool_overrides(args)
    runtime_tool_overrides = config.merge_tool_setting_layers(
        preset_runtime_tool_overrides,
        cli_runtime_tool_overrides,
    )
    requested_tools = parse_requested_tools(args.tools)
    enable_port_scan, enable_web_fingerprint, enable_directory_scan = resolve_stage_flags(
        args.port_scan or ("nmap" in cli_tool_arg_overrides),
        args.web_fingerprint,
        args.directory_scan or ("dirsearch" in cli_tool_arg_overrides),
    )
    if args.skip_validation and enable_directory_scan:
        raise ValueError("目录扫描依赖存活验证，不能与 --skip-validation 同时使用。")

    with config.override_tool_settings(runtime_tool_overrides):
        scanner = SubdomainScanner()
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
            skip_wildcard=args.skip_wildcard,
            skip_validation=args.skip_validation,
            parallel=not args.serial,
            enable_port_scan=enable_port_scan,
            port_mode=args.port_mode,
            enable_web_fingerprint=enable_web_fingerprint,
            enable_directory_scan=enable_directory_scan,
            preset_summary=config.summarize_scan_preset(preset_name),
            tool_arg_overrides=cli_tool_arg_overrides,
            background=bool(getattr(args, "background", False) or getattr(args, "_background_child", False)),
        )

        with overridden_results_dir(args.results_dir):
            if len(targets) == 1:
                return run_single_scan(
                    scanner,
                    target=targets[0],
                    tools=tools,
                    scan_preset=preset_name,
                    skip_wildcard=args.skip_wildcard,
                    skip_validation=args.skip_validation,
                    parallel=not args.serial,
                    enable_port_scan=enable_port_scan,
                    port_mode=args.port_mode,
                    enable_web_fingerprint=enable_web_fingerprint,
                    enable_directory_scan=enable_directory_scan,
                    output_path=args.output,
                    summary_output=args.summary_output,
                )

            return run_batch_scan(
                scanner,
                targets=targets,
                tools=tools,
                scan_preset=preset_name,
                skip_wildcard=args.skip_wildcard,
                skip_validation=args.skip_validation,
                parallel=not args.serial,
                enable_port_scan=enable_port_scan,
                port_mode=args.port_mode,
                enable_web_fingerprint=enable_web_fingerprint,
                enable_directory_scan=enable_directory_scan,
                summary_output=args.summary_output,
            )


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else list(sys.argv[1:])
    parser = build_parser()
    parsed = parser.parse_args(argv)

    if parsed.background and not parsed._background_child:
        try:
            launched = launch_background_scan(argv)
        except Exception as exc:
            console.print(f"[red]后台扫描启动失败: {exc}[/red]")
            return 1

        console.print(f"[green]后台任务已启动: {launched['job_id']}[/green]")
        console.print(f"[green]PID: {launched['pid']}[/green]")
        console.print(f"[green]状态文件: {launched['status_path']}[/green]")
        console.print(f"[green]日志文件: {launched['log_path']}[/green]")
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
        console.print("\n[yellow]扫描已取消[/yellow]")
        return 1
    except Exception as exc:
        update_background_scan_status(
            parsed,
            status="failed",
            finished_at=datetime.now().isoformat(),
            exit_code=1,
            error=str(exc),
        )
        console.print(f"[red]扫描启动失败: {exc}[/red]")
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
        console.print(f"[green]结果文件: {result['saved_path']}[/green]")
        console.print(f"[green]摘要文件: {result['report_path']}[/green]")
    else:
        stats = result["batch_summary"]["statistics"]
        console.print(f"[green]批量扫描完成: {stats['success_count']}/{stats['total_domains']} 成功[/green]")
        console.print(f"[green]汇总文件: {result['summary_path']}[/green]")
        console.print(f"[green]摘要文件: {result['report_path']}[/green]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
