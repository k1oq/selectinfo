"""
Batch scan runner.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable

import config
from utils import atomic_write_json
from utils.logger import console


class BatchScanRunner:
    """Execute batch scans and build summary output."""

    def __init__(
        self,
        scanner,
        run_port_scan: Callable,
        run_web_fingerprint: Callable | None = None,
        run_directory_scan: Callable | None = None,
    ):
        self.scanner = scanner
        self.run_port_scan = run_port_scan
        self.run_web_fingerprint = run_web_fingerprint
        self.run_directory_scan = run_directory_scan

    def run(
        self,
        domains: list[str],
        tools: list[str],
        skip_wildcard: bool = False,
        skip_validation: bool = False,
        parallel: bool = True,
        enable_port_scan: bool = False,
        port_scan_mode: str | None = None,
        enable_web_fingerprint: bool = False,
        enable_directory_scan: bool = False,
    ) -> tuple[dict, Path]:
        total = len(domains)
        success = 0
        summary_items: list[dict] = []

        for index, domain in enumerate(domains, 1):
            console.print(f"\n[bold cyan][{index}/{total}] {domain}[/bold cyan]")

            try:
                result = self.scanner.scan(
                    target=domain,
                    tools=tools,
                    skip_wildcard=skip_wildcard,
                    skip_validation=skip_validation,
                    parallel=parallel,
                )

                saved_path = self.scanner.save_result()
                item_summary = self.build_item_summary(domain=domain, result=result, saved_path=saved_path)

                if result.get("subdomains"):
                    success += 1

                    if enable_port_scan and not result.get("wildcard", {}).get("detected"):
                        port_results = self.run_port_scan(
                            result["subdomains"],
                            mode=port_scan_mode,
                            output_path=saved_path,
                        )
                        if port_results:
                            item_summary["port_scan_status"] = "completed"
                            item_summary["open_port_count"] = sum(
                                len(ports) for ports in port_results.values()
                            )

                            if enable_web_fingerprint and self.run_web_fingerprint is not None:
                                fingerprint_result = self.run_web_fingerprint(
                                    result["subdomains"],
                                    port_results,
                                    output_path=saved_path,
                                )
                                if fingerprint_result:
                                    item_summary["web_fingerprint_status"] = "completed"
                                    item_summary["web_target_count"] = len(
                                        fingerprint_result.get("targets", [])
                                    )

                                    if enable_directory_scan and self.run_directory_scan is not None:
                                        if fingerprint_result.get("targets"):
                                            directory_result = self.run_directory_scan(
                                                fingerprint_result["targets"],
                                                output_path=saved_path,
                                            )
                                            if directory_result:
                                                item_summary["directory_scan_status"] = "completed"
                                                item_summary["dirsearch_finding_count"] = (
                                                    directory_result.get("statistics", {}).get(
                                                        "interesting_path_count", 0
                                                    )
                                                )
                                            else:
                                                item_summary["directory_scan_status"] = "error"
                                        else:
                                            item_summary["directory_scan_status"] = (
                                                "skipped_no_web_targets"
                                            )
                                else:
                                    item_summary["web_fingerprint_status"] = "error"
                                    if enable_directory_scan:
                                        item_summary["directory_scan_status"] = (
                                            "skipped_no_fingerprint"
                                        )
                        else:
                            item_summary["port_scan_status"] = "no_open_ports"
                            if enable_web_fingerprint:
                                item_summary["web_fingerprint_status"] = "skipped_no_open_ports"
                            if enable_directory_scan:
                                item_summary["directory_scan_status"] = "skipped_no_open_ports"
                    elif enable_port_scan:
                        item_summary["port_scan_status"] = "skipped_wildcard"
                        if enable_web_fingerprint:
                            item_summary["web_fingerprint_status"] = "skipped_wildcard"
                        if enable_directory_scan:
                            item_summary["directory_scan_status"] = "skipped_wildcard"

                summary_items.append(item_summary)
                self.print_item_summary(item_summary)

            except KeyboardInterrupt:
                console.print("\n[yellow]批量扫描已中断[/yellow]")
                break
            except Exception as exc:
                console.print(f"[red]扫描出错: {exc}[/red]")
                summary_items.append(
                    {
                        "domain": domain,
                        "status": "error",
                        "message": str(exc),
                        "saved_path": None,
                        "valid_count": 0,
                        "total_found": 0,
                        "wildcard_detected": False,
                        "tool_runs": {},
                        "port_scan_status": "not_started",
                        "open_port_count": 0,
                        "web_fingerprint_status": "not_started",
                        "web_target_count": 0,
                        "directory_scan_status": "not_started",
                        "dirsearch_finding_count": 0,
                    }
                )

        batch_summary = self.build_summary(summary_items, tools=tools)
        batch_summary["statistics"]["requested_domains"] = total
        batch_summary["statistics"]["completed_success_count"] = success
        summary_path = self.save_summary(batch_summary)
        return batch_summary, summary_path

    @staticmethod
    def build_item_summary(domain: str, result: dict, saved_path: Path | None) -> dict:
        valid_count = len(result.get("subdomains", []))
        wildcard_detected = bool(result.get("wildcard", {}).get("detected"))
        tool_runs = result.get("tool_runs", {})
        failed_tools = {
            name: run
            for name, run in tool_runs.items()
            if run.get("status") in {"error", "timeout"}
        }
        all_tools_failed = bool(tool_runs) and len(failed_tools) == len(tool_runs)

        if valid_count > 0:
            status = "success"
            message = "扫描成功"
        elif all_tools_failed:
            status = "error"
            message = "所有子域名工具都执行失败"
        elif wildcard_detected:
            status = "no_valid_results"
            message = "检测到泛解析，未保留有效子域名"
        else:
            status = "no_valid_results"
            message = "未发现有效子域名"

        if status == "no_valid_results" and failed_tools:
            message = f"{message}（失败工具: {', '.join(sorted(failed_tools))}）"

        return {
            "domain": domain,
            "status": status,
            "message": message,
            "saved_path": str(saved_path) if saved_path else None,
            "valid_count": valid_count,
            "total_found": result.get("statistics", {}).get("total_found", 0),
            "wildcard_detected": wildcard_detected,
            "tool_runs": tool_runs,
            "port_scan_status": "not_started",
            "open_port_count": 0,
            "web_fingerprint_status": "not_started",
            "web_target_count": 0,
            "directory_scan_status": "not_started",
            "dirsearch_finding_count": 0,
        }

    @staticmethod
    def build_summary(summary_items: list[dict], tools: list[str]) -> dict:
        total = len(summary_items)
        success_count = sum(1 for item in summary_items if item["status"] == "success")
        error_count = sum(1 for item in summary_items if item["status"] == "error")
        no_valid_count = sum(1 for item in summary_items if item["status"] == "no_valid_results")
        port_scan_completed = sum(
            1 for item in summary_items if item["port_scan_status"] == "completed"
        )
        web_fingerprint_completed = sum(
            1 for item in summary_items if item["web_fingerprint_status"] == "completed"
        )
        directory_scan_completed = sum(
            1 for item in summary_items if item["directory_scan_status"] == "completed"
        )
        total_open_ports = sum(item.get("open_port_count", 0) for item in summary_items)
        total_web_targets = sum(item.get("web_target_count", 0) for item in summary_items)
        total_dirsearch_findings = sum(
            item.get("dirsearch_finding_count", 0) for item in summary_items
        )

        return {
            "scan_time": datetime.now().isoformat(),
            "tools_used": tools,
            "statistics": {
                "total_domains": total,
                "success_count": success_count,
                "error_count": error_count,
                "no_valid_result_count": no_valid_count,
                "port_scan_completed_count": port_scan_completed,
                "total_open_ports": total_open_ports,
                "web_fingerprint_completed_count": web_fingerprint_completed,
                "directory_scan_completed_count": directory_scan_completed,
                "total_web_targets": total_web_targets,
                "total_dirsearch_findings": total_dirsearch_findings,
            },
            "items": summary_items,
        }

    @staticmethod
    def save_summary(summary: dict) -> Path:
        config.ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = config.RESULTS_DIR / f"batch_summary_{timestamp}.json"
        atomic_write_json(output_path, summary, ensure_ascii=False, indent=2)
        return output_path

    @staticmethod
    def print_item_summary(item: dict):
        status_style = {
            "success": "green",
            "error": "red",
            "no_valid_results": "yellow",
        }.get(item["status"], "white")
        console.print(
            f"[{status_style}]结果: {item['message']} | "
            f"发现 {item['total_found']} 个，保留 {item['valid_count']} 个 | "
            f"端口扫描: {item['port_scan_status']} | "
            f"Web指纹: {item['web_fingerprint_status']} | "
            f"目录扫描: {item['directory_scan_status']}[/{status_style}]"
        )
        if item.get("saved_path"):
            console.print(f"[dim]结果文件: {item['saved_path']}[/dim]")

    @staticmethod
    def print_overview(summary: dict, summary_path: Path):
        from rich.table import Table

        stats = summary["statistics"]
        table = Table(title="批量扫描汇总", show_header=True)
        table.add_column("指标")
        table.add_column("值")
        table.add_row("总域名数", str(stats["total_domains"]))
        table.add_row("成功", str(stats["success_count"]))
        table.add_row("无有效结果", str(stats["no_valid_result_count"]))
        table.add_row("错误", str(stats["error_count"]))
        table.add_row("端口扫描完成", str(stats["port_scan_completed_count"]))
        table.add_row("开放端口总数", str(stats["total_open_ports"]))
        table.add_row("Web 指纹完成", str(stats["web_fingerprint_completed_count"]))
        table.add_row("目录扫描完成", str(stats["directory_scan_completed_count"]))
        table.add_row("Web 目标总数", str(stats["total_web_targets"]))
        table.add_row("目录发现总数", str(stats["total_dirsearch_findings"]))
        console.print()
        console.print(table)
        console.print(f"[green]批量汇总已保存至: {summary_path}[/green]")
