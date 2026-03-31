"""
泛解析检测模块
检测目标域名是否配置了通配符 DNS 记录
"""
import random
import string
import dns.resolver
from typing import Set, List

from utils.logger import get_logger
import config

logger = get_logger(__name__)


class WildcardDetector:
    """泛解析检测器"""
    
    # DNS劫持常见的保留/特殊IP段，这些IP不应该出现在公网解析结果中
    HIJACK_IP_PREFIXES = (
        '127.',          # 本地回环
        '10.',           # 私有地址
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',  # 私有地址
        '192.168.',      # 私有地址
        '198.18.', '198.19.',  # RFC 2544 基准测试地址（常见DNS劫持）
        '0.', '255.',    # 特殊地址
    )
    
    def __init__(self, domain: str):
        """
        初始化检测器
        
        Args:
            domain: 要检测的主域名
        """
        self.domain = domain
        self.wildcard_ips: Set[str] = set()
        self.has_wildcard = False
        self._resolver = dns.resolver.Resolver()
        # 使用公共DNS，避免本地DNS劫持
        self._resolver.nameservers = ['8.8.8.8', '1.1.1.1', '114.114.114.114']
        self._resolver.timeout = config.DNS_TIMEOUT
        self._resolver.lifetime = config.DNS_TIMEOUT
    
    def _generate_random_subdomain(self) -> str:
        """生成一个随机子域名前缀（数字+字母混合，5-8位）"""
        length = random.randint(5, 8)
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def _is_hijack_ip(self, ip: str) -> bool:
        """检查IP是否是DNS劫持常见的保留地址"""
        return ip.startswith(self.HIJACK_IP_PREFIXES)
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """
        解析域名，返回IP列表（过滤掉DNS劫持的保留地址）
        
        Args:
            domain: 要解析的域名
            
        Returns:
            IP列表，解析失败返回空列表
        """
        try:
            answers = self._resolver.resolve(domain, 'A')
            ips = []
            for rdata in answers:
                ip = str(rdata)
                if self._is_hijack_ip(ip):
                    logger.debug(f"过滤DNS劫持IP: {ip}")
                    continue
                ips.append(ip)
            return ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"查询 {domain} 出错: {e}")
            return []
    
    def detect(self) -> bool:
        """
        检测域名是否存在泛解析
        
        生成3个随机子域名进行DNS查询，只有当这3个全部都能解析时，
        才判定为存在泛解析。
        
        Returns:
            是否存在泛解析
        """
        logger.info(f"[cyan]正在检测 {self.domain} 的泛解析配置...[/cyan]")
        
        # 生成3个随机子域名
        test_domains = []
        for _ in range(3):
            prefix = self._generate_random_subdomain()
            test_domains.append(f"{prefix}.{self.domain}")
        
        logger.debug(f"测试子域名: {test_domains}")
        
        # 检测每个随机子域名是否能解析
        resolved_count = 0
        for test_domain in test_domains:
            ips = self._resolve_domain(test_domain)
            if ips:
                resolved_count += 1
                self.wildcard_ips.update(ips)
                logger.debug(f"  {test_domain} -> {ips}")
            else:
                logger.debug(f"  {test_domain} -> 无法解析")
        
        # 判断：3个随机子域名必须全部能解析才算泛解析
        self.has_wildcard = (resolved_count == 3)
        
        if self.has_wildcard:
            logger.warning(
                f"[yellow]检测到泛解析! (3/3 随机子域名均可解析)[/yellow]\n"
                f"  泛解析IP: {', '.join(sorted(self.wildcard_ips))}"
            )
        else:
            if resolved_count > 0:
                logger.info(f"[green]未检测到泛解析 ({resolved_count}/3 随机子域名可解析，不满足条件)[/green]")
            else:
                logger.info("[green]未检测到泛解析[/green]")
        
        return self.has_wildcard
    
    def is_wildcard_ip(self, ip: str) -> bool:
        """
        检查IP是否属于泛解析（精确匹配）
        
        Args:
            ip: 要检查的IP地址
            
        Returns:
            是否是泛解析IP
        """
        return ip in self.wildcard_ips
    
    def get_wildcard_ips(self) -> Set[str]:
        """获取泛解析 IP 集合"""
        return self.wildcard_ips.copy()
    
    def get_result(self) -> dict:
        """获取检测结果"""
        return {
            "domain": self.domain,
            "has_wildcard": self.has_wildcard,
            "wildcard_ips": list(self.wildcard_ips),
        }
