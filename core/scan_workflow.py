"""
Shared post-subdomain scan stages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from utils import atomic_write_json, load_json_file
from utils.logger import console

from .directory_scanner import DirectoryScanner
from .port_scanner import PortScanner
from .reverse_ip_scanner import ReverseIPScanner
from .web_fingerprint_scanner import WebFingerprintScanner


def merge_result_field(output_path: Path | str | None, field_name: str, payload: dict[str, Any]):
    """Merge a stage payload back into the persisted JSON result."""
    if not output_path:
        return

    destination = Path(output_path)
    if not destination.exists():
        return

    data = load_json_file(destination)
    data[field_name] = payload
    atomic_write_json(destination, data, ensure_ascii=False, indent=2)


def run_port_scan(
    subdomains: list[dict[str, Any]],
    mode: str | None = None,
    output_path: Path | str | None = None,
) -> dict[str, list[int]]:
    """Run port scanning for the IPs attached to validated subdomains."""
    hosts = sorted({ip for item in subdomains for ip in item.get("ip", [])})
    if not hosts:
        console.print("[yellow]没有可用的 IP，跳过端口扫描。[/yellow]")
        return {}

    console.print("\n[cyan]端口扫描[/cyan]")

    try:
        port_scanner = PortScanner()
        results = port_scanner.scan_hosts(hosts, mode=mode or "common")
        if results:
            merge_result_field(output_path, "port_scan", port_scanner.to_port_scan_dict())
            if output_path:
                console.print(f"\n[green]结果已更新至: {Path(output_path)}[/green]")
        return results
    except KeyboardInterrupt:
        console.print("\n[yellow]端口扫描已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]端口扫描出错: {exc}[/red]")
        return {}


def run_web_fingerprint(
    subdomains: list[dict[str, Any]],
    port_scan_hosts: dict[str, list[int]],
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Run web fingerprinting for previously discovered open ports."""
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
                console.print(f"\n[green]结果已更新至: {Path(output_path)}[/green]")
        return result
    except KeyboardInterrupt:
        console.print("\n[yellow]Web 指纹识别已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]Web 指纹识别出错: {exc}[/red]")
        return {}


def run_reverse_ip(
    target_ip: str,
    open_ports: list[int] | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Run reverse-IP candidate collection for a direct IP target."""
    console.print("\n[cyan]IP 反查[/cyan]")
    try:
        scanner = ReverseIPScanner()
        result = scanner.scan(target_ip, open_ports=open_ports)
        if result:
            merge_result_field(output_path, "reverse_ip", result)
            if output_path:
                console.print(f"\n[green]缁撴灉宸叉洿鏂拌嚦: {Path(output_path)}[/green]")
        return result
    except KeyboardInterrupt:
        console.print("\n[yellow]IP 反查已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]IP 反查出错: {exc}[/red]")
        return {}


def run_directory_scan(
    web_targets: list[dict[str, Any]],
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Run directory scanning for identified web targets."""
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
                console.print(f"\n[green]结果已更新至: {Path(output_path)}[/green]")
        return result
    except KeyboardInterrupt:
        console.print("\n[yellow]Web 目录扫描已中断[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[red]目录扫描出错: {exc}[/red]")
        return {}
