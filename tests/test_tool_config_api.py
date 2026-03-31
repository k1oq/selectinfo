import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from tools.config_api import ToolConfigAPI


class ToolConfigAPITests(unittest.TestCase):
    def setUp(self):
        self.api = ToolConfigAPI()
        self._original_settings = config.load_local_settings()

    def tearDown(self):
        config.save_local_settings(self._original_settings)

    def test_list_tools(self):
        self.assertEqual(self.api.list_tools(), ["subfinder", "oneforall", "nmap", "dirsearch"])

    def test_get_tool_info_contains_settings(self):
        info = self.api.get_tool_info("nmap")
        self.assertEqual(info["name"], "nmap")
        self.assertIn("settings", info)
        self.assertIn("args", info["settings"])

    def test_update_and_reset_tool_settings(self):
        updated = self.api.update_tool_settings("nmap", {"timeout": 9.5, "threads": 42})
        self.assertTrue(updated["ok"])
        self.assertEqual(updated["settings"]["timeout"], 9.5)
        self.assertEqual(updated["settings"]["threads"], 42)

        reset = self.api.reset_tool_settings("nmap")
        self.assertTrue(reset["ok"])
        self.assertNotEqual(reset["settings"]["threads"], 42)

    def test_invalid_setting_key_raises(self):
        with self.assertRaises(ValueError):
            self.api.update_tool_settings("nmap", {"not_exists": 1})

    def test_set_tool_arg_string_updates_nmap_args(self):
        result = self.api.set_tool_arg_string("nmap", "-sS -Pn")
        self.assertTrue(result["ok"])
        self.assertEqual(result["effective_settings"]["args"], ["-sS", "-Pn"])

    def test_reserved_oneforall_args_are_rejected(self):
        with self.assertRaises(ValueError):
            self.api.set_tool_arg_string("oneforall", "--fmt json")

    def test_reserved_subfinder_args_are_rejected(self):
        with self.assertRaises(ValueError):
            self.api.set_tool_arg_string("subfinder", "-d example.com")

    def test_set_dirsearch_arg_string_updates_extra_args(self):
        result = self.api.set_tool_arg_string("dirsearch", "--exclude-status 404")
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["effective_settings"]["extra_args"],
            ["--exclude-status", "404"],
        )


if __name__ == "__main__":
    unittest.main()
