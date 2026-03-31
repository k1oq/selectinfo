"""
结果合并模块
合并多个工具的扫描结果并去重
"""
from typing import List, Dict, Set
from collections import defaultdict

from utils.logger import get_logger

logger = get_logger(__name__)


class ResultMerger:
    """结果合并器"""
    
    def __init__(self):
        """初始化合并器"""
        self._results: Dict[str, List[str]] = {}
        self._merged: Set[str] = set()
    
    def add_result(self, tool_name: str, subdomains: List[str]):
        """
        添加工具扫描结果
        
        Args:
            tool_name: 工具名称
            subdomains: 子域名列表
        """
        self._results[tool_name] = subdomains
        logger.debug(f"添加 {tool_name} 结果: {len(subdomains)} 个子域名")
    
    def merge(self) -> List[str]:
        """
        合并所有结果并去重
        
        Returns:
            去重后的子域名列表（已排序）
        """
        self._merged = set()
        
        for tool_name, subdomains in self._results.items():
            for subdomain in subdomains:
                # 标准化子域名（小写，去除空格）
                normalized = subdomain.strip().lower()
                if normalized:
                    self._merged.add(normalized)
        
        result = sorted(list(self._merged))
        logger.info(f"[green]合并完成: 共 {len(result)} 个唯一子域名[/green]")
        
        return result
    
    def get_statistics(self) -> Dict:
        """
        获取统计信息
        
        Returns:
            包含各工具结果数量和合并结果的统计字典
        """
        stats = {
            "by_tool": {},
            "total_raw": 0,
            "total_unique": len(self._merged),
            "duplicates_removed": 0,
        }
        
        for tool_name, subdomains in self._results.items():
            stats["by_tool"][tool_name] = len(subdomains)
            stats["total_raw"] += len(subdomains)
        
        stats["duplicates_removed"] = stats["total_raw"] - stats["total_unique"]
        
        return stats
    
    def get_tool_coverage(self) -> Dict[str, Dict]:
        """
        获取各工具的覆盖情况
        
        Returns:
            每个工具独有和共有的子域名统计
        """
        coverage = {}
        
        for tool_name, subdomains in self._results.items():
            tool_set = set(s.strip().lower() for s in subdomains if s.strip())
            
            # 计算该工具独有的子域名
            unique_to_tool = tool_set.copy()
            for other_tool, other_subs in self._results.items():
                if other_tool != tool_name:
                    other_set = set(s.strip().lower() for s in other_subs if s.strip())
                    unique_to_tool -= other_set
            
            coverage[tool_name] = {
                "total": len(tool_set),
                "unique": len(unique_to_tool),
                "shared": len(tool_set) - len(unique_to_tool),
            }
        
        return coverage
    
    def clear(self):
        """清空所有结果"""
        self._results.clear()
        self._merged.clear()


def merge_results(results: List[List[str]]) -> List[str]:
    """
    便捷函数：合并多个结果列表
    
    Args:
        results: 多个子域名列表
        
    Returns:
        合并去重后的子域名列表
    """
    merged = set()
    for result in results:
        for subdomain in result:
            normalized = subdomain.strip().lower()
            if normalized:
                merged.add(normalized)
    return sorted(list(merged))
