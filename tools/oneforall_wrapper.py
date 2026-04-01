"""
OneForAll wrapper.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List
from uuid import uuid4

import config
from utils.logger import get_logger
from .base import BaseTool
from .download_utils import download_oneforall_repo

logger = get_logger(__name__)


class OneForAllTool(BaseTool):
    """OneForAll subdomain enumeration wrapper."""

    name = "oneforall"
    description = "综合性子域名收集工具，支持多数据源"

    def __init__(self):
        super().__init__()
        self.default_tool_dir = config.ONEFORALL_DIR
        self.tool_dir, self.script_path = self._resolve_paths()
        self.results_dir = self.tool_dir / "results"

    def _resolve_paths(self) -> tuple[Path, Path]:
        configured_path = config.get_tool_path(self.name)
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if candidate.is_dir():
                return candidate, candidate / "oneforall.py"
            if candidate.exists():
                return candidate.parent, candidate
            logger.debug(f"OneForAll configured path does not exist, falling back: {candidate}")

        return self.default_tool_dir, self.default_tool_dir / "oneforall.py"

    def is_installed(self) -> bool:
        self.tool_dir, self.script_path = self._resolve_paths()
        self.results_dir = self.tool_dir / "results"
        return self.script_path.exists()

    def install(self) -> bool:
        logger.warning(f"[yellow]请手动克隆 OneForAll 到: {self.tool_dir}[/yellow]")
        logger.info("命令: git clone https://github.com/shmilylty/OneForAll.git tools/oneforall")
        return False

    def get_expected_location(self) -> Path | str:
        return self.default_tool_dir

    def configure_path(self, path: str) -> bool:
        candidate = Path(path).expanduser()
        script_path = candidate / "oneforall.py" if candidate.is_dir() else candidate
        if not script_path.exists():
            logger.error(f"[red]OneForAll 路径不存在: {script_path}[/red]")
            return False

        config.set_tool_path(self.name, str(script_path.parent.resolve()))
        self.tool_dir = script_path.parent.resolve()
        self.script_path = script_path.resolve()
        self.results_dir = self.tool_dir / "results"
        logger.info(f"[green]已保存 OneForAll 路径: {self.tool_dir}[/green]")
        return True

    def supports_download(self) -> bool:
        return True

    def download(self) -> bool:
        success = download_oneforall_repo(self.default_tool_dir)
        if success:
            config.set_tool_path(self.name, str(self.default_tool_dir.resolve()))
            self.tool_dir = self.default_tool_dir.resolve()
            self.script_path = self.tool_dir / "oneforall.py"
            self.results_dir = self.tool_dir / "results"
        return success

    def _build_output_path(self, domain: str, fmt: str) -> Path:
        config.ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace("*", "_").replace("/", "_").replace("\\", "_")
        filename = f"{safe_domain}_{timestamp}_{uuid4().hex[:8]}.{fmt}"
        return config.ONEFORALL_EXPORTS_DIR / filename

    def scan(self, domain: str) -> List[str]:
        if not self.is_installed():
            message = f"OneForAll 未安装，请将项目克隆到 {self.tool_dir}"
            self.set_last_run(status="error", message=message)
            logger.error(message)
            return []

        logger.info(f"[cyan]使用 OneForAll 扫描 {domain}...[/cyan]")
        settings = config.get_tool_settings(self.name)
        fmt = str(settings.get("fmt", "csv")).strip().lower()
        if fmt not in {"csv", "json"}:
            logger.warning(f"[yellow]OneForAll fmt={fmt} 当前不受支持，已回退为 csv[/yellow]")
            fmt = "csv"

        output_path = self._build_output_path(domain, fmt)
        cmd = [
            sys.executable,
            str(self.script_path),
            "--target",
            domain,
            "--alive",
            str(settings.get("alive", False)),
            "--brute",
            str(settings.get("brute", False)),
            "--fmt",
            fmt,
            "--path",
            str(output_path),
            *settings.get("extra_args", []),
            "run",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.tool_dir),
                capture_output=True,
                text=True,
                timeout=int(settings.get("timeout", 1800)),
            )
        except subprocess.TimeoutExpired:
            message = "OneForAll 扫描超时"
            self.set_last_run(status="timeout", message=message)
            logger.error(message)
            return []
        except Exception as exc:
            message = f"OneForAll 扫描出错: {exc}"
            self.set_last_run(status="error", message=message)
            logger.error(message)
            return []

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip() or f"return code {result.returncode}"
            message = f"OneForAll 执行失败: {detail.splitlines()[0]}"
            self.set_last_run(
                status="error",
                return_code=result.returncode,
                message=message,
            )
            logger.warning(f"OneForAll 返回非零状态码: {result.returncode}")
            logger.debug(f"stderr: {result.stderr}")
            logger.debug(f"stdout: {result.stdout}")
            return []

        try:
            subdomains, raw_count = self._parse_results(output_path, domain, fmt)
        except FileNotFoundError:
            message = f"OneForAll 执行完成但未生成结果文件: {output_path}"
            self.set_last_run(
                status="error",
                return_code=result.returncode,
                message=message,
            )
            logger.error(message)
            return []
        except Exception as exc:
            message = f"解析 OneForAll 结果失败: {exc}"
            self.set_last_run(
                status="error",
                return_code=result.returncode,
                message=message,
            )
            logger.error(message)
            return []

        message = f"OneForAll 发现 {len(subdomains)} 个子域名"
        if raw_count == 0:
            message = f"OneForAll 完成但未导出任何结果: {output_path}"
            logger.warning(message)
        elif len(subdomains) == 0:
            message = f"OneForAll 导出了 {raw_count} 条记录，但都未通过域名归属过滤"
            logger.warning(message)

        self.set_last_run(
            status="completed",
            return_code=result.returncode,
            message=message,
            raw_count=raw_count,
            valid_count=len(subdomains),
        )
        logger.info(f"[green]{message}[/green]")
        return subdomains

    def _parse_results(self, result_file: Path, domain: str, fmt: str) -> tuple[List[str], int]:
        if not result_file.exists():
            raise FileNotFoundError(result_file)

        raw_count = 0
        subdomains: set[str] = set()

        if fmt == "json":
            with open(result_file, "r", encoding="utf-8", errors="ignore") as file:
                payload = json.load(file) or []
            for row in payload:
                if not isinstance(row, dict):
                    continue
                candidate = self.normalize_candidate(row.get("subdomain") or row.get("url") or "")
                if not candidate:
                    continue
                raw_count += 1
                if self.belongs_to_domain(candidate, domain):
                    subdomains.add(candidate)
            return sorted(subdomains), raw_count

        with open(result_file, "r", encoding="utf-8", errors="ignore") as file:
            reader = csv.DictReader(file)
            for row in reader:
                candidate = self.normalize_candidate(row.get("subdomain") or row.get("url") or "")
                if not candidate:
                    continue
                raw_count += 1
                if self.belongs_to_domain(candidate, domain):
                    subdomains.add(candidate)

        return sorted(subdomains), raw_count

    def get_version(self) -> str:
        if not self.is_installed():
            return "未安装"

        try:
            version_file = self.tool_dir / "oneforall" / "__version__.py"
            if version_file.exists():
                with open(version_file, "r", encoding="utf-8", errors="ignore") as file:
                    content = file.read()
                for line in content.splitlines():
                    if "__version__" in line:
                        return line.split("=", 1)[1].strip().strip("\"'")
        except Exception:
            pass
        return "unknown"
