import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from tools.dirsearch_wrapper import DirsearchTool
from tools.oneforall_wrapper import OneForAllTool
from tools.subfinder_wrapper import SubfinderTool


class ToolWrapperFallbackTests(unittest.TestCase):
    def setUp(self):
        self._original_settings = config.load_local_settings()

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def test_subfinder_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("subfinder", "C:/missing/subfinder.exe")
        tool = SubfinderTool()
        self.assertEqual(tool.executable, tool.default_executable)
        self.assertTrue(tool.is_installed())

    def test_oneforall_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("oneforall", "C:/missing/oneforall.py")
        tool = OneForAllTool()
        self.assertEqual(tool.tool_dir, tool.default_tool_dir)
        self.assertEqual(tool.script_path, tool.default_tool_dir / "oneforall.py")
        self.assertTrue(tool.is_installed())

    def test_dirsearch_falls_back_to_default_when_configured_path_is_missing(self):
        config.set_tool_path("dirsearch", "C:/missing/dirsearch.py")
        tool = DirsearchTool()
        self.assertEqual(tool.executable, tool.default_executable)
        self.assertTrue(tool.is_installed())
