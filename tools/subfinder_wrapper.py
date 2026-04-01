"""
Subfinder wrapper.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

import config
from utils.logger import get_logger
from .base import BaseTool
from .download_utils import download_subfinder_release
from .tool_manager import ToolManager

logger = get_logger(__name__)


class SubfinderTool(BaseTool):
    """Subfinder subdomain enumeration wrapper."""

    name = "subfinder"
    description = "快速被动子域名枚举工具"

    def __init__(self):
        super().__init__()
        self.tool_dir = config.SUBFINDER_DIR
        platform_info = ToolManager.get_platform_info()
        self.executable_name = "subfinder.exe" if platform_info["is_windows"] else "subfinder"
        self.default_executable = self.tool_dir / self.executable_name
        self.executable = self._resolve_executable()

    def _resolve_executable(self) -> Path:
        configured_path = config.get_tool_path(self.name)
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if candidate.exists():
                return candidate
            logger.debug(f"Subfinder configured path does not exist, falling back: {candidate}")
        return self.default_executable

    def is_installed(self) -> bool:
        self.executable = self._resolve_executable()
        return self.executable.exists()

    def install(self) -> bool:
        logger.warning(f"[yellow]请手动下载 Subfinder 并放到: {self.tool_dir}[/yellow]")
        logger.info("下载地址: https://github.com/projectdiscovery/subfinder/releases")
        return False

    def get_expected_location(self) -> Path | str:
        return self.default_executable

    def configure_path(self, path: str) -> bool:
        candidate = Path(path).expanduser()
        if candidate.is_dir():
            candidate = candidate / self.executable_name

        if not candidate.exists():
            logger.error(f"[red]Subfinder 路径不存在: {candidate}[/red]")
            return False

        config.set_tool_path(self.name, str(candidate.resolve()))
        self.executable = candidate.resolve()
        logger.info(f"[green]已保存 Subfinder 路径: {self.executable}[/green]")
        return True

    def supports_download(self) -> bool:
        return True

    def download(self) -> bool:
        platform_info = ToolManager.get_platform_info()
        success = download_subfinder_release(
            self.default_executable,
            system=platform_info["system"],
            arch=platform_info["arch"],
        )
        if success:
            config.set_tool_path(self.name, str(self.default_executable.resolve()))
            self.executable = self.default_executable.resolve()
        return success

    def scan(self, domain: str) -> List[str]:
        if not self.is_installed():
            message = f"Subfinder 未安装，请将可执行文件放到 {self.tool_dir}"
            self.set_last_run(status="error", message=message)
            logger.error(message)
            return []

        logger.info(f"[cyan]使用 Subfinder 扫描 {domain}...[/cyan]")
        settings = config.get_tool_settings(self.name)
        cmd = [str(self.executable), *config.get_subfinder_config_args(), "-d", domain]
        if settings.get("silent", True):
            cmd.append("-silent")
        if settings.get("use_all", True):
            cmd.append("-all")
        cmd.extend(settings.get("extra_args", []))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(settings.get("timeout", 600)),
                env=config.get_subfinder_runtime_env(),
            )
        except subprocess.TimeoutExpired:
            message = "Subfinder 扫描超时"
            self.set_last_run(status="timeout", message=message)
            logger.error(message)
            return []
        except Exception as exc:
            message = f"Subfinder 扫描出错: {exc}"
            self.set_last_run(status="error", message=message)
            logger.error(message)
            return []

        raw_candidates = [
            self.normalize_candidate(line)
            for line in (result.stdout or "").splitlines()
            if self.normalize_candidate(line)
        ]

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip() or f"return code {result.returncode}"
            message = f"Subfinder 执行失败: {detail.splitlines()[0]}"
            self.set_last_run(
                status="error",
                return_code=result.returncode,
                message=message,
                raw_count=len(raw_candidates),
                valid_count=0,
            )
            logger.error(message)
            return []

        subdomains = sorted(
            {
                candidate
                for candidate in raw_candidates
                if self.belongs_to_domain(candidate, domain)
            }
        )
        message = f"Subfinder 发现 {len(subdomains)} 个子域名"
        self.set_last_run(
            status="completed",
            return_code=result.returncode,
            message=message,
            raw_count=len(raw_candidates),
            valid_count=len(subdomains),
        )
        logger.info(f"[green]{message}[/green]")
        return subdomains

    def get_version(self) -> str:
        if not self.is_installed():
            return "未安装"

        try:
            result = subprocess.run(
                [str(self.executable), *config.get_subfinder_config_args(), "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                env=config.get_subfinder_runtime_env(),
            )
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                return output.splitlines()[0]
        except Exception:
            pass
        return "unknown"
