"""
Port scanning module.

This module runs nmap against a list of IPs and merges the result back into the
project's JSON output format.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from typing import Dict, List

import config
from utils.logger import get_logger

logger = get_logger(__name__)


class PortScanner:
    """Port scanner backed by nmap."""

    def __init__(self, timeout: float = 1800.0, threads: int = 200):
        nmap_settings = config.get_tool_settings("nmap")
        # This timeout is the total subprocess timeout for one nmap run.
        self.timeout = float(nmap_settings.get("timeout", timeout))
        self.threads = int(nmap_settings.get("threads", threads))
        self._results: Dict[str, List[int]] = {}
        self._scan_mode = ""
        self._nmap_checked = False

        self.nmap_path = config.get_tool_path("nmap", getattr(config, "NMAP_PATH", "nmap"))
        self.nmap_args = list(
            nmap_settings.get(
                "args",
                getattr(config, "NMAP_DEFAULT_ARGS", ["-sS", "-Pn", "-T4"]),
            )
        )

    def _check_nmap_available(self) -> bool:
        """
        Check whether nmap is available in the current environment.

        Check order:
        1. Resolved instance path
        2. config.NMAP_PATH
        3. System PATH
        4. tools/nmap local binary
        """
        if self._nmap_checked:
            return bool(self.nmap_path)

        candidates: List[str] = []

        if self.nmap_path:
            candidates.append(str(self.nmap_path))

        if getattr(config, "NMAP_PATH", None):
            candidates.append(str(config.NMAP_PATH))

        candidates.append("nmap")

        tools_dir = getattr(config, "TOOLS_DIR", None)
        if tools_dir is not None:
            tools_dir = Path(tools_dir)
            local_nmap = tools_dir / "nmap" / ("nmap.exe" if sys.platform.startswith("win") else "nmap")
            candidates.append(str(local_nmap))

        unique_candidates: List[str] = []
        seen = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            unique_candidates.append(candidate)

        for path in unique_candidates:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self.nmap_path = path
                    self._nmap_checked = True
                    logger.info(f"[green]检测到可用的 nmap: {path}[/green]")
                    return True
            except FileNotFoundError:
                continue
            except Exception as exc:
                logger.debug(f"检测 nmap 路径 {path} 出错: {exc}")
                continue

        self._nmap_checked = True
        self.nmap_path = ""

        if sys.platform.startswith("linux"):
            logger.error(
                "[red]未检测到可用的 nmap。\n"
                "请先在系统中安装 nmap（如 apt/yum），或将 nmap 二进制放到项目目录：\n"
                f"  {tools_dir / 'nmap'}\n"
                "例如将可执行文件命名为 'nmap' 并放到该目录下，然后重新运行。[/red]"
            )
        elif sys.platform.startswith("win"):
            logger.error(
                "[red]未检测到可用的 nmap。\n"
                "请从 https://nmap.org/download.html 下载 Windows 版 nmap，"
                "并在系统 PATH 中配置，或将 nmap.exe 放到:\n"
                f"  {tools_dir / 'nmap'}\n"
                "并在 config.NMAP_PATH 中设置正确的路径。[/red]"
            )
        else:
            logger.error(
                "[red]未检测到可用的 nmap，请安装 nmap 并保证在 PATH 中，"
                "或在 config.NMAP_PATH 中配置其绝对路径。[/red]"
            )

        return False

    def _build_nmap_command(self, hosts: List[str], ports: List[int]) -> List[str]:
        """Build the nmap command."""
        port_spec = ",".join(str(port) for port in sorted(set(ports)))

        cmd = [self.nmap_path]
        cmd.extend(self.nmap_args)
        cmd.extend(["-p", port_spec, "-oG", "-"])
        cmd.extend(hosts)
        return cmd

    def _parse_nmap_grepable(self, output: str) -> Dict[str, List[int]]:
        """Parse nmap grepable output into an ip -> open ports mapping."""
        results: Dict[str, List[int]] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("Host:"):
                continue

            try:
                parts = line.split("Ports:")
                if len(parts) != 2:
                    continue

                host_part, ports_part = parts[0], parts[1].strip()
                host_fields = host_part.split()
                if len(host_fields) < 2:
                    continue

                ip = host_fields[1]
                open_ports: List[int] = []

                for port_item in ports_part.split(","):
                    port_item = port_item.strip()
                    if not port_item:
                        continue

                    fields = port_item.split("/")
                    if len(fields) < 2:
                        continue

                    port_str, state = fields[0], fields[1]
                    if state != "open":
                        continue

                    try:
                        open_ports.append(int(port_str))
                    except ValueError:
                        continue

                if open_ports:
                    results.setdefault(ip, []).extend(open_ports)
            except Exception as exc:
                logger.error(f"[red]解析 nmap 输出行出错: {exc}[/red]")
                continue

        for ip in list(results.keys()):
            results[ip] = sorted(set(results[ip]))
            if not results[ip]:
                del results[ip]

        return results

    def scan_hosts(self, hosts: List[str], mode: str | None = None) -> Dict[str, List[int]]:
        """Scan the given hosts with nmap using the selected port preset."""
        if not hosts:
            logger.warning("[yellow]未提供任何主机，跳过端口扫描[/yellow]")
            return {}

        if mode is None:
            mode = "common"

        if mode not in config.PORT_PRESETS:
            logger.error(f"未知的扫描模式: {mode}")
            return {}

        if not self._check_nmap_available():
            return {}

        ports = config.load_ports(mode)
        if not ports:
            logger.warning("[yellow]端口列表为空，跳过端口扫描[/yellow]")
            return {}

        self._scan_mode = mode
        self._results = {host: [] for host in hosts}

        mode_name = config.PORT_PRESETS[mode]["name"]
        logger.info(f"[cyan]端口扫描 (nmap): {len(hosts)} 个目标 × {len(ports)} 个端口 [{mode_name}][/cyan]")
        logger.info(f"[dim]nmap 总超时: {self.timeout:.0f} 秒[/dim]")

        cmd = self._build_nmap_command(hosts, ports)
        logger.debug(f"nmap 命令: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                f"[red]nmap 扫描超时（当前总超时: {self.timeout:.0f} 秒），"
                "请适当减少目标或端口数量，或增大超时时间[/red]"
            )
            return {}
        except Exception as exc:
            logger.error(f"[red]nmap 扫描出错: {exc}[/red]")
            return {}

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            logger.error(f"[red]nmap 返回非零状态码 {result.returncode}: {stderr}[/red]")
            return {}

        parsed = self._parse_nmap_grepable(result.stdout or "")
        self._results.update(parsed)

        total_open = sum(len(ports) for ports in self._results.values())
        logger.info(f"[green]发现 {total_open} 个开放端口[/green]")

        if total_open == 0:
            return {}

        for host in list(self._results.keys()):
            self._results[host] = sorted(set(self._results[host]))
            if not self._results[host]:
                del self._results[host]

        logger.info(
            f"[green]完成: 共 {len(self._results)} 个 IP，{total_open} 个开放端口[/green]"
        )
        return self._results

    def to_port_scan_dict(self) -> dict:
        """Return the merged port_scan payload."""
        return {
            "scan_time": datetime.now().isoformat(),
            "scan_mode": self._scan_mode,
            "statistics": {
                "total_ips": len(self._results),
                "total_open_ports": sum(len(ports) for ports in self._results.values()),
            },
            "hosts": self._results,
        }

    def to_json(self) -> dict:
        """Backward-compatible JSON output wrapper."""
        return self.to_port_scan_dict()

    def save_result(self, output_path: Path | None = None) -> Path:
        """Save the current port scan result to disk."""
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(config.RESULTS_DIR) / f"portscan_{ts}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(self.to_json(), file, ensure_ascii=False, indent=2)

        logger.info(f"[green]结果已保存: {output_path}[/green]")
        return output_path
