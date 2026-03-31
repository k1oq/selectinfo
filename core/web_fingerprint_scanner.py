"""
Web fingerprinting pipeline.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import config
from tools.setup_manager import NmapSetupManager
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PortFingerprintCandidate:
    ip: str
    ports: list[int]


class WebFingerprintScanner:
    """Identify web services with nmap based on previously discovered open ports."""

    def __init__(
        self,
        nmap_path: str | None = None,
        timeout: int | None = None,
    ):
        self.nmap_path = nmap_path or NmapSetupManager.detect_path()
        self.timeout = int(timeout or config.WEB_FINGERPRINT_TIMEOUT)

    def scan(self, subdomains: list[dict], port_scan_hosts: dict[str, list[int]]) -> dict[str, Any]:
        """Run web fingerprinting only."""
        ip_candidates = self._build_ip_candidates(port_scan_hosts)
        subdomain_index = self._build_subdomain_index(subdomains)

        fingerprint_result = {
            "scan_time": datetime.now().isoformat(),
            "statistics": {
                "candidate_endpoint_count": sum(len(candidate.ports) for candidate in ip_candidates),
                "web_target_count": 0,
                "fingerprint_error_count": 0,
            },
            "targets": [],
        }

        if not ip_candidates:
            return fingerprint_result

        if not self.nmap_path:
            logger.warning("[yellow]nmap 当前不可用，跳过 Web 指纹识别[/yellow]")
            fingerprint_result["statistics"]["fingerprint_error_count"] = len(ip_candidates)
            return fingerprint_result

        ip_port_web_map: dict[tuple[str, int], dict[str, Any]] = {}
        for candidate in ip_candidates:
            ok, xml_output = self._fingerprint_ip(candidate)
            if not ok:
                fingerprint_result["statistics"]["fingerprint_error_count"] += 1
                continue

            for port_id, nmap_info in self._parse_ip_fingerprint(xml_output).items():
                ip_port_web_map[(candidate.ip, port_id)] = nmap_info

        targets = self._map_web_targets(subdomain_index, ip_port_web_map)
        fingerprint_result["targets"] = targets
        fingerprint_result["statistics"]["web_target_count"] = len(targets)
        return fingerprint_result

    def _build_ip_candidates(self, port_scan_hosts: dict[str, list[int]]) -> list[PortFingerprintCandidate]:
        candidates: list[PortFingerprintCandidate] = []
        for ip, ports in port_scan_hosts.items():
            normalized_ports = sorted(set(int(port) for port in ports))
            if normalized_ports:
                candidates.append(PortFingerprintCandidate(ip=ip, ports=normalized_ports))
        return candidates

    def _build_subdomain_index(self, subdomains: list[dict[str, Any]]) -> dict[str, list[str]]:
        subdomain_index: dict[str, list[str]] = {}
        for item in subdomains:
            subdomain = item.get("subdomain")
            ips = item.get("ip", [])
            if not subdomain:
                continue
            for ip in ips:
                subdomain_index.setdefault(ip, [])
                if subdomain not in subdomain_index[ip]:
                    subdomain_index[ip].append(subdomain)
        return subdomain_index

    def _fingerprint_ip(self, candidate: PortFingerprintCandidate) -> tuple[bool, str]:
        command = [
            self.nmap_path,
            *config.WEB_FINGERPRINT_NMAP_ARGS,
            "-p",
            ",".join(str(port) for port in candidate.ports),
            "-oX",
            "-",
            candidate.ip,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"[yellow]Web 指纹超时: {candidate.ip}[/yellow]")
            return False, ""
        except Exception as exc:
            logger.error(f"[red]Web 指纹出错: {candidate.ip} -> {exc}[/red]")
            return False, ""

        if result.returncode != 0:
            logger.warning(
                f"[yellow]nmap Web 指纹返回非零状态码 {result.returncode}: {candidate.ip}[/yellow]"
            )
            return False, result.stderr or result.stdout or ""
        return True, result.stdout or ""

    def _parse_ip_fingerprint(self, xml_output: str) -> dict[int, dict[str, str]]:
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            logger.warning(f"[yellow]nmap XML 解析失败: {exc}[/yellow]")
            return {}

        targets: dict[int, dict[str, str]] = {}
        for port_element in root.findall(".//port"):
            state_element = port_element.find("state")
            state = state_element.attrib.get("state", "") if state_element is not None else ""
            if state != "open":
                continue

            port_id = int(port_element.attrib.get("portid", "0") or 0)
            service_element = port_element.find("service")
            scripts = {script.attrib.get("id", ""): script for script in port_element.findall("script")}
            nmap_info = self._extract_nmap_info(service_element, scripts)
            if self._is_web_service(nmap_info):
                targets[port_id] = nmap_info

        return targets

    def _map_web_targets(
        self,
        subdomain_index: dict[str, list[str]],
        ip_port_web_map: dict[tuple[str, int], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        deduped_targets: dict[tuple[str, str, int], dict[str, Any]] = {}
        for (ip, port), nmap_info in ip_port_web_map.items():
            for subdomain in subdomain_index.get(ip, []):
                scheme = self._determine_scheme(nmap_info)
                url = self._build_url(subdomain, scheme, port)
                key = (scheme, subdomain, port)
                deduped_targets[key] = {
                    "subdomain": subdomain,
                    "ip": ip,
                    "port": port,
                    "scheme": scheme,
                    "url": url,
                    "fingerprint_status": "identified",
                    "nmap": dict(nmap_info),
                }
        return list(deduped_targets.values())

    def _extract_nmap_info(self, service_element: ET.Element | None, scripts: dict[str, ET.Element]) -> dict[str, str]:
        service = service_element.attrib.get("name", "") if service_element is not None else ""
        product = service_element.attrib.get("product", "") if service_element is not None else ""
        version = service_element.attrib.get("version", "") if service_element is not None else ""
        extrainfo = service_element.attrib.get("extrainfo", "") if service_element is not None else ""
        tunnel = service_element.attrib.get("tunnel", "") if service_element is not None else ""

        title_script = scripts.get("http-title")
        server_header_script = scripts.get("http-server-header")
        ssl_cert_script = scripts.get("ssl-cert")

        title = self._script_output(title_script)
        server_header = self._script_output(server_header_script)
        ssl_cert_subject, ssl_cert_issuer = self._extract_ssl_cert_fields(ssl_cert_script)

        if tunnel:
            service = f"{tunnel}/{service}" if service else tunnel

        return {
            "service": service,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
            "title": title,
            "server_header": server_header,
            "ssl_cert_subject": ssl_cert_subject,
            "ssl_cert_issuer": ssl_cert_issuer,
        }

    @staticmethod
    def _script_output(script: ET.Element | None) -> str:
        if script is None:
            return ""
        return (script.attrib.get("output") or "").strip()

    def _extract_ssl_cert_fields(self, script: ET.Element | None) -> tuple[str, str]:
        if script is None:
            return "", ""

        subject = ""
        issuer = ""

        for elem in script.iter():
            key = elem.attrib.get("key", "").lower()
            if key == "subject":
                subject = elem.attrib.get("value", "") or elem.text or subject
            elif key == "issuer":
                issuer = elem.attrib.get("value", "") or elem.text or issuer

        output = self._script_output(script)
        for line in output.splitlines():
            normalized = line.strip()
            if normalized.lower().startswith("subject:") and not subject:
                subject = normalized.split(":", 1)[1].strip()
            elif normalized.lower().startswith("issuer:") and not issuer:
                issuer = normalized.split(":", 1)[1].strip()

        return subject, issuer

    @staticmethod
    def _is_web_service(nmap_info: dict[str, str]) -> bool:
        service = (nmap_info.get("service") or "").lower()
        return "http" in service or bool(nmap_info.get("title")) or bool(nmap_info.get("server_header"))

    @staticmethod
    def _determine_scheme(nmap_info: dict[str, str]) -> str:
        service = (nmap_info.get("service") or "").lower()
        if "https" in service or service.startswith("ssl/") or service.startswith("tls/"):
            return "https"
        return "http"

    @staticmethod
    def _build_url(subdomain: str, scheme: str, port: int) -> str:
        default_port = 443 if scheme == "https" else 80
        if port == default_port:
            return f"{scheme}://{subdomain}"
        return f"{scheme}://{subdomain}:{port}"
