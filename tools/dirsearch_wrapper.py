"""
Dirsearch wrapper used by the directory scan pipeline and tool configuration APIs.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import config
from utils.logger import get_logger

logger = get_logger(__name__)


class DirsearchTool:
    """Thin wrapper around dirsearch."""

    name = "dirsearch"
    description = "Web 目录扫描工具"

    OVERRIDABLE_FLAGS = {
        "--random-agent",
        "--delay",
        "--max-rate",
        "--retries",
        "--exclude-status",
    }

    def __init__(self):
        self.default_executable = config.DIRSEARCH_DIR / "dirsearch.py"
        self.executable = self._resolve_executable()

    def _resolve_executable(self) -> Path:
        configured_path = config.get_tool_path(self.name)
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if candidate.exists():
                return candidate
            logger.debug(f"Dirsearch 配置路径不存在，回退到默认路径: {candidate}")
        return self.default_executable

    def is_installed(self) -> bool:
        self.executable = self._resolve_executable()
        return self.executable.exists()

    def install(self) -> bool:
        logger.warning("[yellow]Dirsearch 当前不支持自动下载，请手动放到 tools/dirsearch/[/yellow]")
        return False

    def get_expected_location(self) -> Path | str:
        return self.default_executable

    def supports_download(self) -> bool:
        return False

    def configure_path(self, path: str) -> bool:
        candidate = Path(path).expanduser()
        if candidate.is_dir():
            for filename in ("dirsearch.py", "dirsearch.exe", "dirsearch"):
                resolved = candidate / filename
                if resolved.exists():
                    candidate = resolved
                    break

        if not candidate.exists():
            logger.error(f"[red]Dirsearch 路径不存在: {candidate}[/red]")
            return False

        config.set_tool_path(self.name, str(candidate.resolve()))
        self.executable = candidate.resolve()
        logger.info(f"[green]已保存 Dirsearch 路径: {self.executable}[/green]")
        return True

    def get_version(self) -> str:
        completed = self.run_help(timeout=15)
        if not completed["ok"]:
            return "unknown"

        output = (completed["stdout"] or completed["stderr"]).strip()
        first_line = output.splitlines()[0].strip() if output else ""
        return first_line or "unknown"

    def build_base_command(self) -> tuple[list[str], str | None]:
        self.executable = self._resolve_executable()
        if self.executable.suffix.lower() == ".py":
            return [sys.executable, str(self.executable)], str(self.executable.parent)
        return [str(self.executable)], str(self.executable.parent)

    def run_help(self, timeout: int = 20) -> dict[str, Any]:
        if not self.is_installed():
            return {"ok": False, "stdout": "", "stderr": "", "message": "dirsearch 未安装"}

        cmd, cwd = self.build_base_command()
        return self._run_command([*cmd, "--help"], timeout=timeout, cwd=cwd)

    def check_json_support(self) -> dict[str, Any]:
        """Validate that dirsearch is executable and exposes JSON output flags."""
        if not self.is_installed():
            return {
                "installed": False,
                "usable": False,
                "path": str(self.executable),
                "version": "",
                "message": f"未找到 dirsearch，期望位置: {self.get_expected_location()}",
            }

        completed = self.run_help(timeout=20)
        if not completed["ok"]:
            return {
                "installed": True,
                "usable": False,
                "path": str(self.executable),
                "version": "",
                "message": completed["message"],
            }

        help_text = "\n".join([completed.get("stdout", ""), completed.get("stderr", "")]).lower()
        usable = "--format" in help_text and "-o" in help_text and "json" in help_text
        return {
            "installed": True,
            "usable": usable,
            "path": str(self.executable),
            "version": self.get_version(),
            "message": "命令可执行且支持 JSON 输出" if usable else "命令可执行，但未检测到 JSON 输出参数",
        }

    def build_scan_command(self, url: str, output_path: Path) -> tuple[list[str], str | None]:
        settings = config.get_tool_settings(self.name)
        cmd, cwd = self.build_base_command()
        effective_extra_args = self._merge_default_args(settings.get("extra_args", []))

        command = [
            *cmd,
            "-u",
            url,
            "--format",
            "json",
            "-o",
            str(output_path),
            "-t",
            str(settings.get("threads", config.DIRSEARCH_THREADS)),
            *effective_extra_args,
        ]
        return command, cwd

    @staticmethod
    def _stringify_command(command: list[str], prefer_posix: bool | None = None) -> str:
        use_posix = prefer_posix if prefer_posix is not None else not sys.platform.startswith("win")
        if use_posix and hasattr(shlex, "join"):
            return shlex.join(command)
        return subprocess.list2cmdline(command)

    def scan_url(self, url: str) -> dict[str, Any]:
        settings = config.get_tool_settings(self.name)

        if not self.is_installed():
            return {
                "status": "skipped_unavailable",
                "command": "",
                "findings": [],
            }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as file:
            output_path = Path(file.name)

        command, cwd = self.build_scan_command(url, output_path)
        completed = self._run_command(
            command,
            timeout=int(settings.get("timeout", config.DIRSEARCH_TIMEOUT)),
            cwd=cwd,
        )

        command_text = self._stringify_command(command)
        if not completed["ok"]:
            output_path.unlink(missing_ok=True)
            return {
                "status": "error",
                "command": command_text,
                "findings": [],
                "message": completed["message"],
            }

        try:
            with open(output_path, "r", encoding="utf-8", errors="ignore") as file:
                payload = json.load(file)
        except Exception as exc:
            output_path.unlink(missing_ok=True)
            return {
                "status": "error",
                "command": command_text,
                "findings": [],
                "message": f"无法解析 dirsearch JSON 报告: {exc}",
            }
        finally:
            output_path.unlink(missing_ok=True)

        return {
            "status": "completed",
            "command": command_text,
            "findings": self._extract_findings(payload),
        }

    def _merge_default_args(self, user_extra_args: list[str]) -> list[str]:
        user_args = list(user_extra_args or [])
        user_flags = self._collect_flags(user_args)
        merged = list(config.DIRSEARCH_DEFAULT_EXTRA_ARGS)

        filtered_defaults: list[str] = []
        index = 0
        while index < len(merged):
            token = merged[index]
            takes_value = self._flag_takes_value(token)
            if token in self.OVERRIDABLE_FLAGS and token in user_flags:
                index += 2 if takes_value else 1
                continue
            filtered_defaults.append(token)
            if takes_value and index + 1 < len(merged):
                filtered_defaults.append(merged[index + 1])
                index += 2
            else:
                index += 1

        return [*filtered_defaults, *user_args]

    @staticmethod
    def _collect_flags(args: list[str]) -> set[str]:
        flags = set()
        for token in args:
            if token.startswith("-"):
                flags.add(token)
        return flags

    @staticmethod
    def _flag_takes_value(flag: str) -> bool:
        return flag in {"--delay", "--max-rate", "--retries", "--exclude-status"}

    def _extract_findings(self, payload: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        def walk(node: Any):
            if isinstance(node, dict):
                status = self._coerce_int(
                    node.get("status")
                    or node.get("statusCode")
                    or node.get("status_code")
                )
                url = str(node.get("url") or node.get("uri") or "").strip()
                path = str(node.get("path") or "").strip()

                if status is not None and (url or path):
                    normalized_path = path or self._path_from_url(url)
                    if normalized_path and self._is_interesting_status(status):
                        findings.append(
                            {
                                "path": normalized_path,
                                "status": status,
                                "size": self._coerce_int(
                                    node.get("size")
                                    or node.get("length")
                                    or node.get("contentLength")
                                    or node.get("content-length")
                                    or 0
                                )
                                or 0,
                                "redirect": str(
                                    node.get("redirect")
                                    or node.get("redirect_to")
                                    or node.get("location")
                                    or ""
                                ),
                            }
                        )

                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)

        unique: dict[tuple[str, int], dict[str, Any]] = {}
        for finding in findings:
            key = (finding["path"], finding["status"])
            unique[key] = finding
        return list(unique.values())

    @staticmethod
    def _is_interesting_status(status: int) -> bool:
        return status in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}

    @staticmethod
    def _path_from_url(url: str) -> str:
        if not url:
            return ""
        parsed = urlparse(url)
        return parsed.path or "/"

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _run_command(command: list[str], timeout: int, cwd: str | None = None) -> dict[str, Any]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
        except FileNotFoundError:
            return {"ok": False, "stdout": "", "stderr": "", "message": "命令不存在或路径无效"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "stdout": "", "stderr": "", "message": f"执行超时（{timeout}s）"}
        except Exception as exc:
            return {"ok": False, "stdout": "", "stderr": "", "message": f"执行失败: {exc}"}

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            detail = stderr or stdout or f"返回码 {result.returncode}"
            return {"ok": False, "stdout": stdout, "stderr": stderr, "message": detail}

        return {
            "ok": True,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "message": "ok",
        }
