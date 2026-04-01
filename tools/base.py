"""
Tool base class and shared helpers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from pathlib import Path
from typing import Any, List
from urllib.parse import urlparse


class BaseTool(ABC):
    """Base class for all wrapped tools."""

    name: str = "base"
    description: str = "基础工具"

    def __init__(self):
        self._last_run = self._build_run_info(status="skipped", message="not_started")

    @abstractmethod
    def scan(self, domain: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def is_installed(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def install(self) -> bool:
        raise NotImplementedError

    def get_version(self) -> str:
        return "unknown"

    def get_expected_location(self) -> Path | str:
        return ""

    def configure_path(self, path: str) -> bool:
        return False

    def supports_download(self) -> bool:
        return False

    def download(self) -> bool:
        return False

    def _build_run_info(
        self,
        *,
        status: str,
        return_code: int | None = None,
        message: str = "",
        raw_count: int = 0,
        valid_count: int = 0,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "return_code": return_code,
            "message": message,
            "raw_count": int(raw_count),
            "valid_count": int(valid_count),
        }

    def set_last_run(
        self,
        *,
        status: str,
        return_code: int | None = None,
        message: str = "",
        raw_count: int = 0,
        valid_count: int = 0,
    ):
        self._last_run = self._build_run_info(
            status=status,
            return_code=return_code,
            message=message,
            raw_count=raw_count,
            valid_count=valid_count,
        )

    def get_last_run(self) -> dict[str, Any]:
        return deepcopy(self._last_run)

    @staticmethod
    def normalize_candidate(candidate: str) -> str:
        text = str(candidate or "").strip().lower().rstrip(".")
        if not text:
            return ""

        if "://" in text:
            parsed = urlparse(text)
            text = (parsed.hostname or "").strip().lower().rstrip(".")

        return text

    @classmethod
    def belongs_to_domain(cls, candidate: str, domain: str) -> bool:
        normalized_candidate = cls.normalize_candidate(candidate)
        normalized_domain = cls.normalize_candidate(domain)
        if not normalized_candidate or not normalized_domain:
            return False
        return normalized_candidate == normalized_domain or normalized_candidate.endswith(
            "." + normalized_domain
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.description})"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
