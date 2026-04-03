"""
Target normalization helpers.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import tldextract


class DomainExtractor:
    """Normalize domains, URLs, and direct IP targets."""

    @staticmethod
    def _extract_hostname(input_str: str) -> str:
        raw = input_str.strip()
        if not raw:
            return ""

        if "://" in raw:
            try:
                parsed = urlparse(raw)
                return (parsed.hostname or parsed.path.split("/")[0]).strip()
            except Exception:
                return raw

        host = raw.split("/", 1)[0].strip()
        if host.startswith("[") and "]" in host:
            return host[1 : host.index("]")]

        if DomainExtractor.is_ip_address(host):
            return host

        if host.count(":") == 1:
            candidate, port = host.rsplit(":", 1)
            if port.isdigit():
                return candidate

        return host

    @staticmethod
    def is_ip_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def is_ip_target(input_str: str) -> bool:
        return DomainExtractor.is_ip_address(DomainExtractor._extract_hostname(input_str))

    @staticmethod
    def extract(input_str: str) -> str:
        hostname = DomainExtractor._extract_hostname(input_str)
        if DomainExtractor.is_ip_address(hostname):
            return hostname

        extracted = tldextract.extract(hostname)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return hostname

    @staticmethod
    def extract_full(input_str: str) -> dict:
        hostname = DomainExtractor._extract_hostname(input_str)
        if DomainExtractor.is_ip_address(hostname):
            return {
                "host": hostname,
                "is_ip": True,
                "subdomain": "",
                "domain": hostname,
                "suffix": "",
                "registered_domain": hostname,
            }

        extracted = tldextract.extract(hostname)
        return {
            "host": hostname,
            "is_ip": False,
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "suffix": extracted.suffix,
            "registered_domain": (
                f"{extracted.domain}.{extracted.suffix}"
                if extracted.domain and extracted.suffix
                else hostname
            ),
        }


if __name__ == "__main__":
    test_cases = [
        "https://www.example.com/path",
        "http://api.sub.example.com",
        "www.example.com",
        "sub.example.com",
        "example.com",
        "https://example.co.uk/test",
        "1.1.1.1",
    ]

    extractor = DomainExtractor()
    for case in test_cases:
        result = extractor.extract(case)
        print(f"{case} -> {result}")
