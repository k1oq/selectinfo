"""
Reverse-IP enrichment helpers for direct IP targets.
"""

from __future__ import annotations

import copy
import socket
import ssl
from datetime import datetime
from pathlib import Path
from typing import Any

import dns.reversename
import dns.resolver
from OpenSSL import crypto

import config
from utils import atomic_write_json, load_json_file
from utils.logger import get_logger

logger = get_logger(__name__)


class ReverseIPScanner:
    """Collect PTR and TLS certificate hostname hints for one IP."""

    def __init__(
        self,
        timeout: int | None = None,
        tls_ports: list[int] | None = None,
    ):
        self.timeout = int(timeout or config.REVERSE_IP_TIMEOUT)
        self.tls_ports = [int(port) for port in (tls_ports or config.REVERSE_IP_TLS_PORTS)]
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def scan(self, target_ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
        domains: dict[str, dict[str, Any]] = {}
        source_counts = {"ptr": 0, "tls_cert": 0}

        for hostname in self._lookup_ptr(target_ip):
            self._record_domain(domains, hostname, source="ptr")
            source_counts["ptr"] += 1

        tls_ports = self._select_tls_ports(open_ports)
        for port in tls_ports:
            for hostname in self._fetch_tls_names(target_ip, port):
                self._record_domain(domains, hostname, source="tls_cert", tls_port=port)
                source_counts["tls_cert"] += 1

        finalized_domains: list[dict[str, Any]] = []
        for hostname, record in sorted(domains.items()):
            resolved_ips = self._resolve_hostname(hostname)
            matches_target = target_ip in resolved_ips
            finalized_domains.append(
                {
                    "domain": hostname,
                    "sources": sorted(record["sources"]),
                    "ports": sorted(record["ports"]),
                    "resolved_ips": resolved_ips,
                    "matches_target": matches_target,
                    "confidence": self._build_confidence(matches_target, record["sources"]),
                }
            )

        return {
            "scan_time": datetime.now().isoformat(),
            "target_ip": target_ip,
            "ports_checked": tls_ports,
            "statistics": {
                "candidate_count": len(finalized_domains),
                "current_match_count": sum(1 for item in finalized_domains if item["matches_target"]),
                "source_counts": source_counts,
            },
            "domains": finalized_domains,
        }

    def _select_tls_ports(self, open_ports: list[int] | None) -> list[int]:
        if open_ports:
            selected = [int(port) for port in open_ports if int(port) in set(self.tls_ports)]
            return sorted(set(selected))
        return sorted(set(self.tls_ports))

    def _lookup_ptr(self, target_ip: str) -> list[str]:
        try:
            reverse_name = dns.reversename.from_address(target_ip)
            answers = self.resolver.resolve(reverse_name, "PTR")
        except Exception:
            return []

        results: list[str] = []
        for answer in answers:
            hostname = self._normalize_hostname(str(answer))
            if hostname:
                results.append(hostname)
        return sorted(set(results))

    def _fetch_tls_names(self, target_ip: str, port: int) -> list[str]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target_ip, int(port)), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as tls_sock:
                    cert_bytes = tls_sock.getpeercert(binary_form=True)
        except Exception:
            return []

        if not cert_bytes:
            return []

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)
        except Exception:
            return []

        names: list[str] = []
        common_name = self._normalize_hostname(cert.get_subject().CN or "")
        if common_name:
            names.append(common_name)

        for index in range(cert.get_extension_count()):
            extension = cert.get_extension(index)
            if extension.get_short_name() != b"subjectAltName":
                continue
            for part in str(extension).split(","):
                token = part.strip()
                if not token.startswith("DNS:"):
                    continue
                hostname = self._normalize_hostname(token[4:])
                if hostname:
                    names.append(hostname)

        return sorted(set(names))

    def _resolve_hostname(self, hostname: str) -> list[str]:
        resolved_ips: set[str] = set()
        for record_type in ("A", "AAAA"):
            try:
                answers = self.resolver.resolve(hostname, record_type)
            except Exception:
                continue
            for answer in answers:
                value = str(answer).strip()
                if value:
                    resolved_ips.add(value)
        return sorted(resolved_ips)

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        candidate = hostname.strip().rstrip(".").lower()
        if not candidate or candidate.startswith("*.") or "." not in candidate:
            return ""
        try:
            socket.inet_pton(socket.AF_INET, candidate)
            return ""
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, candidate)
            return ""
        except OSError:
            pass
        return candidate

    @staticmethod
    def _record_domain(
        domains: dict[str, dict[str, Any]],
        hostname: str,
        *,
        source: str,
        tls_port: int | None = None,
    ):
        if not hostname:
            return
        entry = domains.setdefault(hostname, {"sources": set(), "ports": set()})
        entry["sources"].add(source)
        if tls_port is not None:
            entry["ports"].add(int(tls_port))

    @staticmethod
    def _build_confidence(matches_target: bool, sources: set[str]) -> str:
        if matches_target and len(sources) > 1:
            return "high"
        if matches_target:
            return "medium"
        return "low"


def merge_reverse_ip_into_scan_result(scan_result: dict[str, Any], reverse_ip_result: dict[str, Any]) -> dict[str, Any]:
    target_ip = str(scan_result.get("target", "") or "")
    existing_items = list(scan_result.get("subdomains", []))
    merged_items: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in existing_items:
        name = str(item.get("subdomain", "") or "").strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        merged_items.append(item)

    matched_domains = sorted(
        (
            domain_info
            for domain_info in reverse_ip_result.get("domains", [])
            if domain_info.get("matches_target")
        ),
        key=lambda item: item.get("domain", ""),
    )
    for domain_info in matched_domains:
        hostname = str(domain_info.get("domain", "") or "").strip().lower()
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        merged_items.append(
            {
                "subdomain": hostname,
                "ip": [target_ip] if target_ip else [],
                "alive_verified": True,
                "resolved_ips": list(domain_info.get("resolved_ips", [])),
                "reverse_ip_sources": list(domain_info.get("sources", [])),
            }
        )

    scan_result["reverse_ip"] = reverse_ip_result
    scan_result["subdomains"] = merged_items

    stats = scan_result.setdefault("statistics", {})
    stats["total_found"] = len(merged_items)
    stats["valid_count"] = len(merged_items)
    if "total_unique" in stats:
        stats["total_unique"] = len(merged_items)
    return scan_result


def persist_reverse_ip_enrichment(output_path: Path | str, scan_result: dict[str, Any]) -> Path:
    destination = Path(output_path)
    data = load_json_file(destination)
    data["reverse_ip"] = copy.deepcopy(scan_result.get("reverse_ip", {}))
    data["subdomains"] = copy.deepcopy(scan_result.get("subdomains", []))
    data["statistics"] = copy.deepcopy(scan_result.get("statistics", {}))
    atomic_write_json(destination, data, ensure_ascii=False, indent=2)
    return destination
