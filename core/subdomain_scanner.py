"""
子域名扫描调度器
协调多个工具进行扫描
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.table import Table

import config
from utils.logger import get_logger, console
from tools import ToolManager, OneForAllTool, SubfinderTool, BaseTool
from .domain_extractor import DomainExtractor
from .wildcard_detector import WildcardDetector
from .result_merger import ResultMerger
from .subdomain_validator import SubdomainValidator

logger = get_logger(__name__)


class SubdomainScanner:
    """子域名扫描调度器"""
    
    # 可用工具列表
    AVAILABLE_TOOLS = {
        'oneforall': OneForAllTool,
        'subfinder': SubfinderTool,
    }
    
    def __init__(self):
        """初始化扫描器"""
        self.tool_manager = ToolManager()
        self.domain_extractor = DomainExtractor()
        self.result_merger = ResultMerger()
        
        # 注册所有工具
        for name, tool_class in self.AVAILABLE_TOOLS.items():
            self.tool_manager.register_tool(tool_class())
        
        # 扫描结果
        self._scan_result: Optional[Dict] = None
    
    def check_tools(self) -> Dict[str, bool]:
        """检查工具安装状态"""
        return self.tool_manager.check_all()
    
    def scan(
        self,
        target: str,
        tools: List[str] = None,
        skip_wildcard: bool = False,
        skip_validation: bool = False,
        parallel: bool = True,
    ) -> Dict:
        """
        执行子域名扫描
        
        Args:
            target: 目标域名或 URL
            tools: 使用的工具列表，None 表示使用所有已安装的工具
            skip_wildcard: 是否跳过泛解析检测
            skip_validation: 是否跳过验证
            parallel: 是否并行扫描
            
        Returns:
            扫描结果字典
        """
        start_time = datetime.now()
        
        # 提取主域名
        domain = self.domain_extractor.extract(target)
        logger.info(f"[bold]目标域名: {domain}[/bold]")
        
        # 确定使用的工具
        if tools is None:
            tools_to_use = [t for t in self.tool_manager.get_all_tools() if t.is_installed()]
        else:
            tools_to_use = []
            for name in tools:
                tool = self.tool_manager.get_tool(name)
                if tool and tool.is_installed():
                    tools_to_use.append(tool)
                else:
                    logger.warning(f"工具 {name} 未安装或不可用")
        
        if not tools_to_use:
            logger.error("没有可用的扫描工具")
            return {"error": "没有可用的扫描工具"}
        
        logger.info(f"使用工具: {', '.join(t.name for t in tools_to_use)}")
        
        # 泛解析检测
        wildcard_detector = None
        if not skip_wildcard:
            wildcard_detector = WildcardDetector(domain)
            wildcard_detector.detect()
        
        # 执行扫描
        self.result_merger.clear()
        
        if parallel and len(tools_to_use) > 1:
            # 并行扫描
            with ThreadPoolExecutor(max_workers=len(tools_to_use)) as executor:
                futures = {
                    executor.submit(tool.scan, domain): tool 
                    for tool in tools_to_use
                }
                
                for future in as_completed(futures):
                    tool = futures[future]
                    try:
                        subdomains = future.result()
                        self.result_merger.add_result(tool.name, subdomains)
                    except Exception as e:
                        logger.error(f"{tool.name} 扫描失败: {e}")
                        self.result_merger.add_result(tool.name, [])
        else:
            # 串行扫描
            for tool in tools_to_use:
                try:
                    subdomains = tool.scan(domain)
                    self.result_merger.add_result(tool.name, subdomains)
                except Exception as e:
                    logger.error(f"{tool.name} 扫描失败: {e}")
                    self.result_merger.add_result(tool.name, [])
        
        # 合并结果
        merged_subdomains = self.result_merger.merge()
        
        # 验证子域名
        validated_results = []
        filtered_count = 0
        
        if not skip_validation and merged_subdomains:
            validator = SubdomainValidator(wildcard_detector)
            validated_results = validator.validate(merged_subdomains)
            stats = validator.get_statistics()
            filtered_count = stats['wildcard_filtered'] + stats['invalid_count']
        else:
            validated_results = [{'subdomain': s, 'ip': []} for s in merged_subdomains]
        
        # 计算耗时
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # 构建结果
        self._scan_result = {
            "target": domain,
            "scan_time": start_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "tools_used": [t.name for t in tools_to_use],
            "wildcard": {
                "detected": wildcard_detector.has_wildcard if wildcard_detector else False,
                "ips": list(wildcard_detector.get_wildcard_ips()) if wildcard_detector else [],
            },
            "statistics": {
                "total_found": len(merged_subdomains),
                "valid_count": len(validated_results),
                "filtered_count": filtered_count,
                **self.result_merger.get_statistics(),
            },
            "subdomains": validated_results,
        }
        
        self._print_summary()
        
        return self._scan_result
    
    def _print_summary(self):
        """打印扫描摘要"""
        if not self._scan_result:
            return
        
        console.print()
        console.print("[bold green]═══ 扫描完成 ═══[/bold green]")
        
        # 基本信息表格
        table = Table(show_header=False, box=None)
        table.add_column("项目", style="cyan")
        table.add_column("值")
        
        table.add_row("目标域名", self._scan_result["target"])
        table.add_row("扫描耗时", f"{self._scan_result['duration_seconds']} 秒")
        table.add_row("使用工具", ", ".join(self._scan_result["tools_used"]))
        if self._scan_result["wildcard"]["detected"]:
            wildcard_ips = ', '.join(self._scan_result['wildcard']['ips'])
            table.add_row("泛解析", f"[yellow]是 ({wildcard_ips})[/yellow]")
        else:
            table.add_row("泛解析", "[green]否[/green]")
        table.add_row("发现子域名", str(self._scan_result["statistics"]["total_found"]))
        table.add_row("有效子域名", f"[green]{self._scan_result['statistics']['valid_count']}[/green]")
        table.add_row("过滤数量", str(self._scan_result["statistics"]["filtered_count"]))
        
        console.print(table)
        console.print()
    
    def save_result(self, output_path: Path = None) -> Path:
        """
        保存扫描结果
        
        Args:
            output_path: 输出路径，None 则使用默认路径
            
        Returns:
            保存的文件路径
        """
        if not self._scan_result:
            raise ValueError("没有可保存的扫描结果")
        
        if output_path is None:
            config.ensure_dirs()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.RESULTS_DIR / f"{self._scan_result['target']}_{timestamp}.json"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self._scan_result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"结果已保存至: {output_path}")
        return output_path
    
    def get_result(self) -> Optional[Dict]:
        """获取最近一次扫描结果"""
        return self._scan_result
