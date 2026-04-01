"""
Human-friendly CSV summaries for scan results.
"""

from __future__ import annotations

import csv
import io
import tempfile
from pathlib import Path
from typing import Any

from utils import load_json_file


CSV_HEADERS = ["序号", "分组", "名称", "状态", "数值", "详情1", "详情2", "详情3", "备注"]


def default_report_path(source_path: Path | str) -> Path:
    path = Path(source_path)
    return path.with_name(f"{path.stem}.summary.csv")


def write_csv_report(content: str, output_path: Path | str) -> Path:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8-sig",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
            newline="",
        ) as file:
            temp_path = Path(file.name)
            file.write(content)
            file.flush()
        temp_path.replace(destination)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise

    return destination


def write_markdown_report(content: str, output_path: Path | str) -> Path:
    """Backward-compatible alias for older callers."""
    return write_csv_report(content, output_path)


def write_single_scan_report(
    result: dict[str, Any],
    source_path: Path | str,
    output_path: Path | str | None = None,
) -> Path:
    destination = Path(output_path) if output_path else default_report_path(source_path)
    return write_csv_report(build_single_scan_report(result, source_path), destination)


def write_single_scan_report_from_file(
    source_path: Path | str,
    output_path: Path | str | None = None,
) -> Path:
    result = load_json_file(source_path)
    return write_single_scan_report(result, source_path, output_path)


def write_batch_summary_report(
    summary: dict[str, Any],
    source_path: Path | str,
    output_path: Path | str | None = None,
) -> Path:
    destination = Path(output_path) if output_path else default_report_path(source_path)
    return write_csv_report(build_batch_summary_report(summary, source_path), destination)


def write_batch_item_reports(summary: dict[str, Any]) -> list[Path]:
    written: list[Path] = []
    for item in summary.get("items", []):
        saved_path = item.get("saved_path")
        if not saved_path:
            continue
        path = Path(saved_path)
        if not path.exists():
            continue
        written.append(write_single_scan_report_from_file(path))
    return written


def build_single_scan_report(result: dict[str, Any], source_path: Path | str | None = None) -> str:
    stats = result.get("statistics", {})
    wildcard = result.get("wildcard", {})
    tool_runs = result.get("tool_runs", {})
    port_scan = result.get("port_scan", {})
    web_fingerprint = result.get("web_fingerprint", {})
    directory_scan = result.get("directory_scan", {})

    rows: list[list[str]] = []
    order = 1

    def add(section: str, name: str, status: str = "", value: Any = "", detail_1: Any = "", detail_2: Any = "", detail_3: Any = "", note: Any = ""):
        nonlocal order
        rows.append(
            [
                str(order),
                str(section),
                str(name),
                _cell(status),
                _cell(value),
                _cell(detail_1),
                _cell(detail_2),
                _cell(detail_3),
                _cell(note),
            ]
        )
        order += 1

    add("概览", "目标域名", value=result.get("target", "-"))
    add("概览", "结果文件", value=source_path or "-")
    add("概览", "扫描时间", value=result.get("scan_time", "-"))
    add("概览", "扫描耗时(秒)", value=result.get("duration_seconds", "-"))
    add("概览", "使用工具", value=", ".join(result.get("tools_used", [])) or "-")
    add("概览", "泛解析", status="是" if wildcard.get("detected") else "否", value=", ".join(wildcard.get("ips", [])))
    _add_blank_row(rows)

    add("统计", "原始发现数", value=stats.get("total_found", 0))
    add("统计", "有效子域名数", value=stats.get("valid_count", len(result.get("subdomains", []))))
    add("统计", "过滤数量", value=stats.get("filtered_count", 0))
    add("统计", "开放端口总数", value=port_scan.get("statistics", {}).get("total_open_ports", 0))
    add("统计", "Web 目标数", value=web_fingerprint.get("statistics", {}).get("web_target_count", 0))
    add("统计", "目录发现数", value=directory_scan.get("statistics", {}).get("interesting_path_count", 0))

    if tool_runs:
        _add_blank_row(rows)
        for tool_name, info in sorted(tool_runs.items()):
            add(
                "工具状态",
                tool_name,
                status=info.get("status", "-"),
                value=info.get("valid_count", 0),
                detail_1=f"原始 {info.get('raw_count', 0)}",
                detail_2=f"返回码 {info.get('return_code', '-')}",
                note=info.get("message", "-"),
            )

    subdomains = result.get("subdomains", [])
    if subdomains:
        _add_blank_row(rows)
        for item in subdomains:
            ips = ", ".join(item.get("ip", [])) or "-"
            add(
                "子域名",
                item.get("subdomain", "-"),
                value=len(item.get("ip", [])),
                detail_1=ips,
            )

    port_hosts = port_scan.get("hosts", {})
    if port_hosts:
        _add_blank_row(rows)
        for ip, ports in sorted(port_hosts.items()):
            add(
                "开放端口",
                ip,
                value=len(ports),
                detail_1=", ".join(str(port) for port in ports),
            )

    web_targets = web_fingerprint.get("targets", [])
    if web_targets:
        _add_blank_row(rows)
        for target in web_targets:
            nmap_info = target.get("nmap", {})
            add(
                "Web目标",
                target.get("url", "-"),
                status=target.get("fingerprint_status", ""),
                value=target.get("port", ""),
                detail_1=target.get("ip", ""),
                detail_2=nmap_info.get("title", ""),
                detail_3=nmap_info.get("server_header", ""),
            )

    findings = _flatten_directory_findings(directory_scan)
    if findings:
        _add_blank_row(rows)
        for item in findings:
            add(
                "目录发现",
                item["url"],
                status=item["status"],
                value=item["path"],
                detail_1=item["redirect"],
            )

    return _rows_to_csv(rows)


def build_batch_summary_report(summary: dict[str, Any], source_path: Path | str | None = None) -> str:
    stats = summary.get("statistics", {})
    items = summary.get("items", [])

    rows: list[list[str]] = []
    order = 1

    def add(section: str, name: str, status: str = "", value: Any = "", detail_1: Any = "", detail_2: Any = "", detail_3: Any = "", note: Any = ""):
        nonlocal order
        rows.append(
            [
                str(order),
                str(section),
                str(name),
                _cell(status),
                _cell(value),
                _cell(detail_1),
                _cell(detail_2),
                _cell(detail_3),
                _cell(note),
            ]
        )
        order += 1

    add("概览", "汇总文件", value=source_path or "-")
    add("概览", "扫描时间", value=summary.get("scan_time", "-"))
    add("概览", "使用工具", value=", ".join(summary.get("tools_used", [])) or "-")
    _add_blank_row(rows)

    add("统计", "请求域名数", value=stats.get("requested_domains", stats.get("total_domains", 0)))
    add("统计", "成功数", value=stats.get("success_count", 0))
    add("统计", "无有效结果数", value=stats.get("no_valid_result_count", 0))
    add("统计", "错误数", value=stats.get("error_count", 0))
    add("统计", "开放端口总数", value=stats.get("total_open_ports", 0))
    add("统计", "Web 目标总数", value=stats.get("total_web_targets", 0))
    add("统计", "目录发现总数", value=stats.get("total_dirsearch_findings", 0))

    if items:
        _add_blank_row(rows)
        for item in items:
            add(
                "域名概览",
                item.get("domain", "-"),
                status=item.get("status", "-"),
                value=item.get("valid_count", 0),
                detail_1=f"开放端口 {item.get('open_port_count', 0)}",
                detail_2=f"Web目标 {item.get('web_target_count', 0)}",
                detail_3=f"目录发现 {item.get('dirsearch_finding_count', 0)}",
                note=item.get("message", "-"),
            )

    return _rows_to_csv(rows)


def _rows_to_csv(rows: list[list[str]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADERS)
    writer.writerows(rows)
    return buffer.getvalue()


def _add_blank_row(rows: list[list[str]]):
    rows.append([""] * len(CSV_HEADERS))


def _flatten_directory_findings(directory_scan: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target in directory_scan.get("targets", []):
        url = str(target.get("url", "-"))
        for finding in target.get("findings", []):
            findings.append(
                {
                    "url": url,
                    "path": str(finding.get("path", "-")),
                    "status": int(finding.get("status", 0) or 0),
                    "redirect": str(finding.get("redirect", "") or "").strip(),
                }
            )
    return findings


def _cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ").strip()
