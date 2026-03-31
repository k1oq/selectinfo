"""
OneForAll 工具封装
https://github.com/shmilylty/OneForAll

工具需要预先放置在 tools/oneforall/ 目录下
"""
import os
import sys
import csv
import subprocess
from pathlib import Path
from typing import List

import config
from utils.logger import get_logger
from .base import BaseTool
from .download_utils import download_oneforall_repo

logger = get_logger(__name__)


class OneForAllTool(BaseTool):
    """OneForAll 子域名收集工具"""
    
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
            logger.debug(f"OneForAll 配置路径不存在，回退到默认路径: {candidate}")

        return self.default_tool_dir, self.default_tool_dir / "oneforall.py"
    
    def is_installed(self) -> bool:
        """检查 OneForAll 是否已安装"""
        self.tool_dir, self.script_path = self._resolve_paths()
        self.results_dir = self.tool_dir / "results"
        return self.script_path.exists()
    
    def install(self) -> bool:
        """
        提示用户手动安装
        """
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
    
    def scan(self, domain: str) -> List[str]:
        """
        使用 OneForAll 扫描子域名
        
        Args:
            domain: 要扫描的主域名
            
        Returns:
            发现的子域名列表
        """
        if not self.is_installed():
            logger.error(f"OneForAll 未安装，请将项目克隆到: {self.tool_dir}")
            return []
        
        logger.info(f"[cyan]使用 OneForAll 扫描 {domain}...[/cyan]")
        
        try:
            settings = config.get_tool_settings(self.name)
            # 构建命令 - 使用 run 子命令
            cmd = [
                sys.executable,
                str(self.script_path),
                '--target', domain,
                '--alive', str(settings.get("alive", False)),
                '--brute', str(settings.get("brute", False)),
                '--fmt', str(settings.get("fmt", "csv")),
                *settings.get("extra_args", []),
                'run',  # OneForAll 需要 run 子命令
            ]
            
            # 执行扫描
            result = subprocess.run(
                cmd,
                cwd=str(self.tool_dir),
                capture_output=True,
                text=True,
                timeout=int(settings.get("timeout", 1800)),
            )
            
            if result.returncode != 0:
                logger.warning(f"OneForAll 返回非零状态码: {result.returncode}")
                logger.debug(f"stderr: {result.stderr}")
                logger.debug(f"stdout: {result.stdout}")
            
            # 解析结果
            subdomains = self._parse_results(domain)
            logger.info(f"[green]OneForAll 发现 {len(subdomains)} 个子域名[/green]")
            
            return subdomains
            
        except subprocess.TimeoutExpired:
            logger.error("OneForAll 扫描超时")
            return []
        except Exception as e:
            logger.error(f"OneForAll 扫描出错: {e}")
            return []
    
    def _parse_results(self, domain: str) -> List[str]:
        """
        解析 OneForAll 的结果文件
        
        Args:
            domain: 扫描的域名
            
        Returns:
            子域名列表
        """
        subdomains = set()
        
        # 确保结果目录存在
        if not self.results_dir.exists():
            logger.warning(f"结果目录不存在: {self.results_dir}")
            return []
        
        # OneForAll 的结果文件可能有多种命名格式
        possible_files = [
            self.results_dir / f"{domain}.csv",
            self.results_dir / f"{domain}_result.csv",
            self.results_dir / f"all_subdomain_result_{domain}.csv",
        ]
        
        result_file = None
        
        # 先检查预期的文件名
        for f in possible_files:
            if f.exists():
                result_file = f
                break
        
        # 如果没找到，尝试模糊匹配
        if result_file is None:
            for f in self.results_dir.glob(f"*{domain}*.csv"):
                result_file = f
                logger.debug(f"找到结果文件: {f}")
                break
        
        if result_file is None:
            # 列出目录中的所有文件以便调试
            all_files = list(self.results_dir.glob("*.csv"))
            if all_files:
                logger.debug(f"结果目录中的文件: {[f.name for f in all_files]}")
            logger.warning(f"未找到 {domain} 的结果文件")
            return []
        
        logger.debug(f"解析结果文件: {result_file}")
        
        try:
            with open(result_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # OneForAll 结果中子域名字段名为 'subdomain' 或 'url'
                    subdomain = row.get('subdomain', '') or row.get('url', '')
                    subdomain = subdomain.strip()
                    # 清理可能的 URL 格式
                    if subdomain.startswith('http'):
                        from urllib.parse import urlparse
                        subdomain = urlparse(subdomain).hostname or subdomain
                    if subdomain and domain in subdomain:
                        subdomains.add(subdomain.lower())
        except Exception as e:
            logger.error(f"解析结果文件出错: {e}")
        
        return sorted(list(subdomains))
    
    def get_version(self) -> str:
        """获取版本信息"""
        if not self.is_installed():
            return "未安装"
        
        try:
            version_file = self.tool_dir / "oneforall" / "__version__.py"
            if version_file.exists():
                with open(version_file, 'r') as f:
                    content = f.read()
                    # 简单解析版本号
                    for line in content.split('\n'):
                        if '__version__' in line:
                            return line.split('=')[1].strip().strip('"\'')
        except:
            pass
        return "unknown"
