import unittest

from _bootstrap import PROJECT_ROOT  # noqa: F401
from core.result_merger import ResultMerger, merge_results


class ResultMergerTests(unittest.TestCase):
    def test_merge_normalizes_and_deduplicates(self):
        merger = ResultMerger()
        merger.add_result("tool_a", ["WWW.Example.com ", "api.example.com"])
        merger.add_result("tool_b", ["www.example.com", "blog.example.com"])

        merged = merger.merge()

        self.assertEqual(
            merged,
            ["api.example.com", "blog.example.com", "www.example.com"],
        )

    def test_statistics_include_duplicates_removed(self):
        merger = ResultMerger()
        merger.add_result("tool_a", ["www.example.com", "api.example.com"])
        merger.add_result("tool_b", ["www.example.com"])
        merger.merge()

        stats = merger.get_statistics()

        self.assertEqual(stats["total_raw"], 3)
        self.assertEqual(stats["total_unique"], 2)
        self.assertEqual(stats["duplicates_removed"], 1)
        self.assertEqual(stats["by_tool"]["tool_a"], 2)
        self.assertEqual(stats["by_tool"]["tool_b"], 1)

    def test_tool_coverage_reports_unique_and_shared(self):
        merger = ResultMerger()
        merger.add_result("tool_a", ["www.example.com", "api.example.com"])
        merger.add_result("tool_b", ["www.example.com", "blog.example.com"])

        coverage = merger.get_tool_coverage()

        self.assertEqual(coverage["tool_a"]["total"], 2)
        self.assertEqual(coverage["tool_a"]["unique"], 1)
        self.assertEqual(coverage["tool_a"]["shared"], 1)
        self.assertEqual(coverage["tool_b"]["unique"], 1)

    def test_merge_results_helper(self):
        merged = merge_results([
            ["WWW.example.com", "api.example.com"],
            ["www.example.com", "blog.example.com"],
        ])
        self.assertEqual(
            merged,
            ["api.example.com", "blog.example.com", "www.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
