"""
兼容壳：转发到根目录 mcp_server.py。
"""
from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp_server import mcp  # noqa: E402


if __name__ == "__main__":
    mcp.run()
