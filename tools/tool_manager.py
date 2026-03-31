"""
工具管理器
负责工具的检查和状态管理
"""
import platform
from pathlib import Path
from typing import Dict, List, Optional

import config
from utils.logger import get_logger
from .base import BaseTool

logger = get_logger(__name__)


class ToolManager:
    """工具管理器"""
    
    def __init__(self):
        """初始化工具管理器"""
        config.ensure_dirs()
        self._tools: Dict[str, BaseTool] = {}
    
    def register_tool(self, tool: BaseTool):
        """注册工具"""
        self._tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """获取工具实例"""
        return self._tools.get(name)
    
    def get_all_tools(self) -> List[BaseTool]:
        """获取所有已注册的工具"""
        return list(self._tools.values())
    
    def get_available_tools(self) -> List[BaseTool]:
        """获取所有已安装的工具"""
        return [t for t in self._tools.values() if t.is_installed()]
    
    def check_all(self) -> Dict[str, bool]:
        """检查所有工具状态"""
        return {name: tool.is_installed() for name, tool in self._tools.items()}
    
    @staticmethod
    def get_platform_info() -> dict:
        """获取平台信息"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        # 标准化架构名称
        arch_map = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'x64': 'amd64',
            'aarch64': 'arm64',
            'arm64': 'arm64',
            'i386': '386',
            'i686': '386',
        }
        
        arch = arch_map.get(machine, machine)
        
        return {
            'system': system,
            'arch': arch,
            'is_windows': system == 'windows',
            'is_linux': system == 'linux',
            'is_macos': system == 'darwin',
        }
