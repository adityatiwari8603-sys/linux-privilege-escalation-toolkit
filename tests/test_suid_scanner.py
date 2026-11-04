import os
import stat
import tempfile
import unittest

from modules.suid_scanner import scan_suid_sgid


class TestSuidScanner(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_directory = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_test_file(self, filename, mode):
        file_path = os.path.join(self.test_directory, filename)

        with open(file_path, "w") as file:
            file.write("Harmless security scanner test file")

        os.chmod(file_path, mode)
        return file_path

    def test_detects_suid_file(self):
        file_path = self.create_test_file(
            "test_suid",
            0o4755
        )

        results = scan_suid_sgid([self.test_directory])

        detected_paths = [
            finding["path"] for finding in results["findings"]
        ]

        self.assertIn(file_path, detected_paths)

    def test_detects_sgid_file(self):
        file_path = self.create_test_file(
            "test_sgid",
            0o2755
        )

        results = scan_suid_sgid([self.test_directory])

        detected_paths = [
            finding["path"] for finding in results["findings"]
        ]

        self.assertIn(file_path, detected_paths)

    def test_ignores_normal_file(self):
        file_path = self.create_test_file(
            "normal_file",
            0o644
        )

        results = scan_suid_sgid([self.test_directory])

        detected_paths = [
            finding["path"] for finding in results["findings"]
        ]

        self.assertNotIn(file_path, detected_paths)

    def test_returns_expected_structure(self):
        results = scan_suid_sgid([self.test_directory])

        self.assertIn("scanned_files", results)
        self.assertIn("total_findings", results)
        self.assertIn("findings", results)
        self.assertIn("errors", results)

    def test_detects_both_permission_bits(self):
        file_path = self.create_test_file(
            "test_both",
            0o6755
        )

        results = scan_suid_sgid([self.test_directory])

        finding = next(
            item for item in results["findings"]
            if item["path"] == file_path
        )

        self.assertTrue(finding["suid"])
        self.assertTrue(finding["sgid"])


if __name__ == "__main__":
    unittest.main()
