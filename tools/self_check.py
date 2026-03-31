"""
Tool self-check helpers.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

if __package__ in (None, ""):
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    import config
    from tools.dirsearch_wrapper import DirsearchTool
    from tools.oneforall_wrapper import OneForAllTool
    from tools.setup_manager import NmapSetupManager
    from tools.subfinder_wrapper import SubfinderTool
else:
    import config
    from .dirsearch_wrapper import DirsearchTool
    from .oneforall_wrapper import OneForAllTool
    from .setup_manager import NmapSetupManager
    from .subfinder_wrapper import SubfinderTool


@dataclass
class ToolCheckResult:
    name: str
    installed: bool
    usable: bool
    path: str
    version: str = ""
    message: str = ""


class ToolSelfChecker:
    """Run structured checks against local tools."""

    def __init__(self):
        self.subfinder = SubfinderTool()
        self.oneforall = OneForAllTool()
        self.dirsearch = DirsearchTool()

    def run_all(self) -> Dict[str, ToolCheckResult]:
        return {
            "subfinder": self.check_subfinder(),
            "oneforall": self.check_oneforall(),
            "nmap": self.check_nmap(),
            "dirsearch": self.check_dirsearch(),
        }

    def check_subfinder(self) -> ToolCheckResult:
        tool = self.subfinder
        installed = tool.is_installed()
        path = str(tool.executable)

        if not installed:
            return ToolCheckResult(
                name=tool.name,
                installed=False,
                usable=False,
                path=path,
                message=f"未找到可执行文件，期望位置: {tool.get_expected_location()}",
            )

        completed = self._run_command(
            [str(tool.executable), *config.get_subfinder_config_args(), "-version"],
            timeout=15,
            env=config.get_subfinder_runtime_env(),
        )
        if not completed["ok"]:
            return ToolCheckResult(
                name=tool.name,
                installed=True,
                usable=False,
                path=path,
                message=completed["message"],
            )

        version_output = (completed["stdout"] or completed["stderr"]).strip()
        version = version_output.splitlines()[0] if version_output else tool.get_version()
        return ToolCheckResult(
            name=tool.name,
            installed=True,
            usable=True,
            path=path,
            version=version or "unknown",
            message="命令可执行",
        )

    def check_oneforall(self) -> ToolCheckResult:
        tool = self.oneforall
        installed = tool.is_installed()
        path = str(tool.script_path)

        if not installed:
            return ToolCheckResult(
                name=tool.name,
                installed=False,
                usable=False,
                path=path,
                message=f"未找到 oneforall.py，期望位置: {tool.get_expected_location()}",
            )

        completed = self._run_command(
            [sys.executable, str(tool.script_path), "--help"],
            timeout=20,
            cwd=str(tool.tool_dir),
        )
        if not completed["ok"]:
            return ToolCheckResult(
                name=tool.name,
                installed=True,
                usable=False,
                path=path,
                message=completed["message"],
            )

        return ToolCheckResult(
            name=tool.name,
            installed=True,
            usable=True,
            path=path,
            version=tool.get_version() or "unknown",
            message="脚本可执行",
        )

    def check_nmap(self) -> ToolCheckResult:
        detected_path = NmapSetupManager.detect_path()
        expected = str(NmapSetupManager.get_expected_location())

        if not detected_path:
            return ToolCheckResult(
                name="nmap",
                installed=False,
                usable=False,
                path=expected,
                message=f"未检测到 nmap，可配置路径或放到: {expected}",
            )

        completed = self._run_command([detected_path, "--version"], timeout=15)
        if not completed["ok"]:
            return ToolCheckResult(
                name="nmap",
                installed=True,
                usable=False,
                path=detected_path,
                message=completed["message"],
            )

        version_output = (completed["stdout"] or completed["stderr"]).strip()
        version = version_output.splitlines()[0] if version_output else "unknown"
        return ToolCheckResult(
            name="nmap",
            installed=True,
            usable=True,
            path=detected_path,
            version=version,
            message="命令可执行",
        )

    def check_dirsearch(self) -> ToolCheckResult:
        tool = self.dirsearch
        probe = tool.check_json_support()
        return ToolCheckResult(
            name=tool.name,
            installed=bool(probe["installed"]),
            usable=bool(probe["usable"]),
            path=str(probe["path"]),
            version=str(probe.get("version") or ""),
            message=str(probe.get("message") or ""),
        )

    @staticmethod
    def _run_command(
        command: list[str],
        timeout: int = 15,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> dict:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
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
            return {
                "ok": False,
                "stdout": stdout,
                "stderr": stderr,
                "message": f"执行失败: {ToolSelfChecker._summarize_output(detail)}",
            }

        return {
            "ok": True,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "message": "ok",
        }

    @staticmethod
    def _summarize_output(output: str, max_length: int = 120) -> str:
        line = next((line.strip() for line in output.splitlines() if line.strip()), "") or output.strip()
        if len(line) <= max_length:
            return line
        return f"{line[: max_length - 3]}..."


def _print_results(results: Dict[str, ToolCheckResult]):
    for name, result in results.items():
        if result.usable:
            status = "OK"
        elif result.installed:
            status = "BROKEN"
        else:
            status = "MISSING"

        print(f"[{status}] {name}")
        print(f"  path: {result.path or '-'}")
        print(f"  version: {result.version or '-'}")
        print(f"  message: {result.message or '-'}")


if __name__ == "__main__":
    _print_results(ToolSelfChecker().run_all())
