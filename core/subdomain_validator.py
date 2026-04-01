"""
子域名验证模块
过滤泛解析结果并验证子域名存活（仅DNS验证）
"""
import dns.resolver
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

import config
from utils.logger import get_logger, console
from .wildcard_detector import WildcardDetector

logger = get_logger(__name__)


class SubdomainValidator:
    """子域名验证器"""
    
    def __init__(self, wildcard_detector: WildcardDetector = None):
        """
        初始化验证器
        
        Args:
            wildcard_detector: 泛解析检测器实例
        """
        self.wildcard_detector = wildcard_detector
        self._resolver = dns.resolver.Resolver()
        # 使用公共DNS，避免本地DNS劫持
        self._resolver.nameservers = ['8.8.8.8', '1.1.1.1', '114.114.114.114']
        self._resolver.timeout = config.DNS_TIMEOUT
        self._resolver.lifetime = config.DNS_TIMEOUT
        
        # 验证结果缓存
        self._valid_subdomains: List[Dict] = []
        self._invalid_count = 0
        self._wildcard_filtered = 0
    
    def validate(
        self, 
        subdomains: List[str], 
        threads: int = None,
        show_progress: bool = True
    ) -> List[Dict]:
        """
        验证子域名列表
        
        Args:
            subdomains: 待验证的子域名列表
            threads: 并发线程数
            show_progress: 是否显示进度条
            
        Returns:
            有效子域名列表，每个元素包含 subdomain 和 ip
        """
        if threads is None:
            threads = config.DNS_THREADS
        
        self._valid_subdomains = []
        self._invalid_count = 0
        self._wildcard_filtered = 0
        
        total = len(subdomains)
        logger.info(f"[cyan]开始验证 {total} 个子域名...[/cyan]")
        
        if self.wildcard_detector and self.wildcard_detector.has_wildcard:
            logger.info(f"泛解析过滤 - IP: {', '.join(self.wildcard_detector.get_wildcard_ips())}")
        
        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("验证子域名", total=total)
                
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {
                        executor.submit(self._check_single, subdomain): subdomain 
                        for subdomain in subdomains
                    }
                    
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            self._valid_subdomains.append(result)
                        progress.update(task, advance=1)
        else:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                results = executor.map(self._check_single, subdomains)
                for result in results:
                    if result:
                        self._valid_subdomains.append(result)
        
        # 按子域名排序
        self._valid_subdomains.sort(key=lambda x: x['subdomain'])
        
        logger.info(
            f"[green]验证完成: {len(self._valid_subdomains)} 个有效, "
            f"{self._wildcard_filtered} 个泛解析过滤, "
            f"{self._invalid_count} 个无法解析[/green]"
        )
        
        return self._valid_subdomains
    
    def _check_single(self, subdomain: str) -> Dict | None:
        """
        检查单个子域名（仅DNS验证）
        
        Args:
            subdomain: 子域名
            
        Returns:
            有效则返回包含 subdomain 和 ip 的字典，否则返回 None
        """
        try:
            answers = self._resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # 如果存在泛解析检测器，进行过滤
            if self.wildcard_detector and self.wildcard_detector.has_wildcard:
                # 检查所有IP是否都是泛解析IP
                all_wildcard = all(
                    self.wildcard_detector.is_wildcard_ip(ip) 
                    for ip in ips
                )
                if all_wildcard:
                    self._wildcard_filtered += 1
                    return None
            
            return {
                'subdomain': subdomain,
                'ip': sorted(ips),
                'alive_verified': True,
            }
            
        except dns.resolver.NXDOMAIN:
            self._invalid_count += 1
            return None
        except dns.resolver.NoAnswer:
            # 没有 A 记录，尝试获取 CNAME
            try:
                cname_answers = self._resolver.resolve(subdomain, 'CNAME')
                cnames = [str(rdata.target).rstrip('.') for rdata in cname_answers]
                return {
                    'subdomain': subdomain,
                    'ip': [],
                    'cname': cnames,
                    'alive_verified': True,
                }
            except:
                self._invalid_count += 1
                return None
        except dns.resolver.NoNameservers:
            self._invalid_count += 1
            return None
        except dns.exception.Timeout:
            self._invalid_count += 1
            return None
        except Exception:
            self._invalid_count += 1
            return None
    
    def get_statistics(self) -> Dict:
        """获取验证统计信息"""
        return {
            "valid_count": len(self._valid_subdomains),
            "invalid_count": self._invalid_count,
            "wildcard_filtered": self._wildcard_filtered,
            "total_processed": len(self._valid_subdomains) + self._invalid_count + self._wildcard_filtered,
        }
    
    def get_valid_subdomains(self) -> List[str]:
        """获取有效子域名列表（仅子域名字符串）"""
        return [item['subdomain'] for item in self._valid_subdomains]
    
    def get_results_with_ip(self) -> List[Dict]:
        """获取带 IP 的完整结果"""
        return self._valid_subdomains.copy()
