"""
Directory scanning pipeline for previously identified web targets.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import config
from tools.dirsearch_wrapper import DirsearchTool


class DirectoryScanner:
    """Run dirsearch against identified web targets."""

    def __init__(self, dirsearch_tool: DirsearchTool | None = None):
        self.dirsearch_tool = dirsearch_tool or DirsearchTool()

    def scan(self, web_targets: list[dict[str, Any]]) -> dict[str, Any]:
        targets = self._normalize_targets(web_targets)
        result = {
            "scan_time": datetime.now().isoformat(),
            "statistics": {
                "target_count": len(targets),
                "completed_count": 0,
                "error_count": 0,
                "skipped_unavailable_count": 0,
                "interesting_path_count": 0,
            },
            "targets": targets,
        }

        if not targets:
            return result

        dirsearch_probe = self.dirsearch_tool.check_json_support()
        if not dirsearch_probe["usable"]:
            for target in targets:
                target["status"] = "skipped_unavailable"
                target["command"] = ""
                target["findings"] = []
            result["statistics"]["skipped_unavailable_count"] = len(targets)
            return result

        max_workers = min(config.DIRSEARCH_MAX_WORKERS, len(targets))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.dirsearch_tool.scan_url, target["url"]): index
                for index, target in enumerate(targets)
            }
            for future in as_completed(futures):
                index = futures[future]
                target = targets[index]
                try:
                    dirsearch_result = future.result()
                except Exception as exc:
                    dirsearch_result = {
                        "status": "error",
                        "command": "",
                        "findings": [],
                        "message": str(exc),
                    }

                target["status"] = dirsearch_result["status"]
                target["command"] = dirsearch_result.get("command", "")
                target["findings"] = dirsearch_result.get("findings", [])
                if "message" in dirsearch_result:
                    target["message"] = dirsearch_result["message"]

                if dirsearch_result["status"] == "completed":
                    result["statistics"]["completed_count"] += 1
                    result["statistics"]["interesting_path_count"] += len(target["findings"])
                elif dirsearch_result["status"] == "error":
                    result["statistics"]["error_count"] += 1
                elif dirsearch_result["status"] == "skipped_unavailable":
                    result["statistics"]["skipped_unavailable_count"] += 1

        return result

    @staticmethod
    def _normalize_targets(web_targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[tuple[str, str, int], dict[str, Any]] = {}
        for item in web_targets:
            subdomain = item.get("subdomain")
            scheme = item.get("scheme")
            port = int(item.get("port", 0) or 0)
            url = item.get("url")
            if not subdomain or not scheme or not url or not port:
                continue

            deduped[(scheme, subdomain, port)] = {
                "subdomain": subdomain,
                "ip": item.get("ip", ""),
                "port": port,
                "scheme": scheme,
                "url": url,
            }
        return list(deduped.values())
