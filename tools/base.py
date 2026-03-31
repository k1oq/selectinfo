"""
工具基类
定义所有扫描工具的统一接口
"""
from abc import ABC, abstractmethod
from typing import List
from pathlib import Path


class BaseTool(ABC):
    """扫描工具基类"""
    
    name: str = "base"
    description: str = "基础工具"
    
    def __init__(self):
        """初始化工具"""
        pass
    
    @abstractmethod
    def scan(self, domain: str) -> List[str]:
        """
        执行扫描，返回子域名列表
        
        Args:
            domain: 要扫描的主域名
            
        Returns:
            发现的子域名列表
        """
        raise NotImplementedError
    
    @abstractmethod
    def is_installed(self) -> bool:
        """
        检查工具是否已安装
        
        Returns:
            工具是否可用
        """
        raise NotImplementedError
    
    @abstractmethod
    def install(self) -> bool:
        """
        安装/下载工具
        
        Returns:
            安装是否成功
        """
        raise NotImplementedError
    
    def get_version(self) -> str:
        """
        获取工具版本
        
        Returns:
            版本字符串
        """
        return "unknown"

    def get_expected_location(self) -> Path | str:
        """返回工具默认期望路径。"""
        return ""

    def configure_path(self, path: str) -> bool:
        """配置工具路径，默认不支持。"""
        return False

    def supports_download(self) -> bool:
        """工具是否支持自动下载。"""
        return False

    def download(self) -> bool:
        """下载工具，默认不支持。"""
        return False
    
    def __str__(self) -> str:
        return f"{self.name} ({self.description})"
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
