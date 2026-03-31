"""
首次运行时的工具检测、配置与下载支持。
"""
from __future__ import annotations

from pathlib import Path

import config
from utils.logger import get_logger
from .download_utils import detect_nmap_path
from .tool_manager import ToolManager

logger = get_logger(__name__)


class NmapSetupManager:
    """nmap 检测与路径配置。"""

    name = "nmap"

    @staticmethod
    def get_expected_location() -> Path:
        if ToolManager.get_platform_info()["is_windows"]:
            return config.TOOLS_DIR / "nmap" / "nmap.exe"
        return config.TOOLS_DIR / "nmap" / "nmap"

    @staticmethod
    def configure_path(path: str) -> bool:
        candidate = Path(path).expanduser()
        if candidate.is_dir():
            executable_name = "nmap.exe" if ToolManager.get_platform_info()["is_windows"] else "nmap"
            candidate = candidate / executable_name

        if not candidate.exists():
            logger.error(f"[red]nmap 路径不存在: {candidate}[/red]")
            return False

        config.set_tool_path("nmap", str(candidate.resolve()))
        logger.info(f"[green]已保存 nmap 路径: {candidate.resolve()}[/green]")
        return True

    @classmethod
    def detect_path(cls) -> str:
        return detect_nmap_path(cls.get_expected_location())

    @classmethod
    def is_available(cls) -> bool:
        return bool(cls.detect_path())

    @staticmethod
    def supports_download() -> bool:
        return False


def record_backlog_items(todo_path: Path):
    """记录当前已确认的待办。"""
    content = """# TODO

- 优化批量扫描流程与结果汇总，提升批量任务的可读性和可追踪性。
- 为 `core/` 下的关键纯逻辑模块补充最小单元测试。
"""
    todo_path.write_text(content, encoding="utf-8")
