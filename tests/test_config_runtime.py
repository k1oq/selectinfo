import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _bootstrap import PROJECT_ROOT  # noqa: F401
import config
from utils.json_io import atomic_write_json, load_json_file


def _normalize_requirement_name(line: str) -> str:
    requirement = line.split(";", 1)[0].strip()
    if not requirement or requirement.startswith("#"):
        return ""
    for separator in ("[", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if separator in requirement:
            requirement = requirement.split(separator, 1)[0]
            break
    return requirement.strip().lower().replace("_", "-")


class ConfigRuntimeTests(unittest.TestCase):
    def test_override_tool_settings_is_temporary(self):
        original_settings = config.load_local_settings()
        original_nmap_args = config.get_tool_settings("nmap")["args"]

        with config.override_tool_settings({"nmap": {"args": ["-sV", "-Pn"]}}):
            self.assertEqual(config.get_tool_settings("nmap")["args"], ["-sV", "-Pn"])

        self.assertEqual(config.get_tool_settings("nmap")["args"], original_nmap_args)
        self.assertEqual(config.load_local_settings(), original_settings)

    def test_standard_scan_preset_matches_default_tool_settings(self):
        self.assertEqual(
            config.get_scan_preset_tool_settings("standard"),
            config.DEFAULT_TOOL_SETTINGS,
        )

    def test_quick_and_deep_scan_presets_apply_expected_tool_settings(self):
        quick = config.get_scan_preset_tool_settings("quick")
        deep = config.get_scan_preset_tool_settings("deep")

        self.assertEqual(config.get_scan_preset_subdomain_tools("quick"), ["subfinder", "oneforall"])
        self.assertEqual(config.get_scan_preset_subdomain_tools("standard"), ["subfinder", "oneforall"])
        self.assertEqual(config.get_scan_preset_subdomain_tools("deep"), ["subfinder", "oneforall"])
        self.assertEqual(
            config.resolve_scan_preset_subdomain_tools("quick", available_tools=["oneforall"]),
            ["oneforall"],
        )

        self.assertEqual(quick["subfinder"]["timeout"], 300)
        self.assertFalse(quick["subfinder"]["use_all"])
        self.assertEqual(quick["oneforall"]["timeout"], 600)
        self.assertFalse(quick["oneforall"]["brute"])
        self.assertEqual(
            quick["nmap"]["args"],
            [*config.NMAP_DEFAULT_ARGS, "--max-retries", "1"],
        )
        self.assertEqual(quick["dirsearch"]["threads"], 4)

        self.assertEqual(deep["subfinder"]["timeout"], 900)
        self.assertTrue(deep["oneforall"]["brute"])
        self.assertEqual(deep["nmap"]["timeout"], 1200)
        self.assertEqual(
            deep["nmap"]["args"],
            [*config.NMAP_DEFAULT_ARGS, "--max-retries", "3"],
        )
        self.assertEqual(deep["dirsearch"]["threads"], 12)

    def test_root_requirements_cover_bundled_tool_requirements(self):
        root_lines = Path(PROJECT_ROOT, "requirements.txt").read_text(encoding="utf-8").splitlines()
        oneforall_lines = Path(PROJECT_ROOT, "tools", "oneforall", "requirements.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        dirsearch_requirements = Path(PROJECT_ROOT, "tools", "dirsearch", "requirements.txt")
        dirsearch_lines = (
            dirsearch_requirements.read_text(encoding="utf-8").splitlines()
            if dirsearch_requirements.exists()
            else []
        )

        root_requirements = {_normalize_requirement_name(line) for line in root_lines}
        root_requirements.discard("")

        bundled_requirements = {
            _normalize_requirement_name(line) for line in [*oneforall_lines, *dirsearch_lines]
        }
        bundled_requirements.discard("")

        self.assertTrue(bundled_requirements.issubset(root_requirements))

    def test_subfinder_runtime_config_files_are_regenerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp_dir = Path(tmp)
            runtime_home = temp_dir / "subfinder_home"
            config_dir = runtime_home / ".config" / "subfinder"
            config_file = config_dir / "config.yaml"
            provider_file = config_dir / "provider-config.yaml"

            with mock.patch.object(config, "SUBFINDER_RUNTIME_HOME", runtime_home), mock.patch.object(
                config, "SUBFINDER_CONFIG_DIR", config_dir
            ), mock.patch.object(
                config, "SUBFINDER_CONFIG_FILE", config_file
            ), mock.patch.object(
                config, "SUBFINDER_PROVIDER_CONFIG_FILE", provider_file
            ):
                env = config.get_subfinder_runtime_env()

            self.assertEqual(env["HOME"], str(runtime_home))
            self.assertTrue(config_file.exists())
            self.assertTrue(provider_file.exists())

    def test_load_local_settings_warns_when_json_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "local_settings.json"
            settings_file.write_text("{invalid json", encoding="utf-8")

            with mock.patch.object(config, "LOCAL_SETTINGS_FILE", settings_file), self.assertLogs(
                config.logger.name, level="WARNING"
            ) as captured:
                data = config.load_local_settings()

        self.assertEqual(data, {})
        self.assertTrue(any("本地配置" in message for message in captured.output))

    def test_atomic_write_json_does_not_replace_existing_file_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "result.json"
            atomic_write_json(output_path, {"before": True})

            with mock.patch("utils.json_io.json.dump", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    atomic_write_json(output_path, {"after": True})

            self.assertEqual(load_json_file(output_path), {"before": True})


if __name__ == "__main__":
    unittest.main()
