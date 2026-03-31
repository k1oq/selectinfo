"""
主域名提取模块
从用户输入中提取主域名
"""
import tldextract
from urllib.parse import urlparse


class DomainExtractor:
    """主域名提取器"""
    
    @staticmethod
    def extract(input_str: str) -> str:
        """
        从输入中提取主域名
        
        支持的输入格式:
        - https://www.example.com/path
        - http://sub.example.com
        - www.example.com
        - sub.example.com
        - example.com
        
        Args:
            input_str: 用户输入的域名或URL
            
        Returns:
            主域名，如 example.com
        """
        # 清理输入
        input_str = input_str.strip()
        
        # 如果没有协议，添加一个以便解析
        if not input_str.startswith(('http://', 'https://')):
            input_str = 'http://' + input_str
        
        # 解析URL获取主机部分
        try:
            parsed = urlparse(input_str)
            hostname = parsed.hostname or parsed.path.split('/')[0]
        except Exception:
            hostname = input_str
        
        # 使用 tldextract 提取主域名
        extracted = tldextract.extract(hostname)
        
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        
        # 如果提取失败，返回原始主机名
        return hostname
    
    @staticmethod
    def extract_full(input_str: str) -> dict:
        """
        提取完整的域名信息
        
        Args:
            input_str: 用户输入的域名或URL
            
        Returns:
            包含 subdomain, domain, suffix, registered_domain 的字典
        """
        input_str = input_str.strip()
        
        if not input_str.startswith(('http://', 'https://')):
            input_str = 'http://' + input_str
        
        try:
            parsed = urlparse(input_str)
            hostname = parsed.hostname or parsed.path.split('/')[0]
        except Exception:
            hostname = input_str
        
        extracted = tldextract.extract(hostname)
        
        return {
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "suffix": extracted.suffix,
            "registered_domain": f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else hostname,
        }


if __name__ == "__main__":
    # 测试
    test_cases = [
        "https://www.example.com/path",
        "http://api.sub.example.com",
        "www.example.com",
        "sub.example.com",
        "example.com",
        "https://example.co.uk/test",
    ]
    
    extractor = DomainExtractor()
    for case in test_cases:
        result = extractor.extract(case)
        print(f"{case} -> {result}")
