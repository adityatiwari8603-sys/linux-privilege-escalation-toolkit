import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from modules.cron_scanner import inspect_cron_file


class TestCronScanner(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(
            self.temp_dir.name,
            "test_cron"
        )

        with open(self.test_file, "w", encoding="utf-8") as file:
            file.write("# Temporary cron test file\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_secure_cron_file(self, mock_group, mock_owner):
        os.chmod(self.test_file, 0o644)

        result = inspect_cron_file(self.test_file)

        self.assertTrue(result["exists"])
        self.assertEqual(result["owner"], "root")
        self.assertEqual(result["permissions"], "0o644")
        self.assertEqual(result["issues"], [])

    @patch("modules.cron_scanner.get_owner_name", return_value="kali")
    @patch("modules.cron_scanner.get_group_name", return_value="kali")
    def test_non_root_owned_cron_file(self, mock_group, mock_owner):
        os.chmod(self.test_file, 0o644)

        result = inspect_cron_file(self.test_file)

        self.assertTrue(
            any(
                issue["issue"] == "Cron configuration is not owned by root"
                for issue in result["issues"]
            )
        )

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_group_writable_cron_file(self, mock_group, mock_owner):
        os.chmod(self.test_file, 0o664)

        result = inspect_cron_file(self.test_file)

        self.assertTrue(
            any(
                issue["issue"] == "Group-writable cron file or directory"
                for issue in result["issues"]
            )
        )

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_world_writable_cron_file(self, mock_group, mock_owner):
        os.chmod(self.test_file, 0o666)

        result = inspect_cron_file(self.test_file)

        self.assertTrue(
            any(
                issue["severity"] == "CRITICAL"
                and issue["issue"] == "World-writable cron file or directory"
                for issue in result["issues"]
            )
        )

    def test_missing_cron_file(self):
        missing_path = os.path.join(
            self.temp_dir.name,
            "missing_cron"
        )

        result = inspect_cron_file(missing_path)

        self.assertFalse(result["exists"])
        self.assertIn("File or directory not found", result["errors"])


    def test_parse_system_cron_entry(self):
        from modules.cron_scanner import parse_cron_line

        job = parse_cron_line(
            "17 * * * * root /usr/bin/example",
            system_crontab=True
        )

        self.assertEqual(job["schedule"], "17 * * * *")
        self.assertEqual(job["username"], "root")
        self.assertTrue(job["runs_as_root"])
        self.assertEqual(job["command"], "/usr/bin/example")

    def test_parse_environment_assignment_in_command(self):
        from modules.cron_scanner import parse_cron_line

        job = parse_cron_line(
            "30 3 * * 0 root SERVICE_MODE=1 /usr/bin/example",
            system_crontab=True
        )

        self.assertIsNotNone(job)
        self.assertEqual(job["username"], "root")
        self.assertIn("SERVICE_MODE=1", job["command"])

    def test_ignore_environment_assignment_line(self):
        from modules.cron_scanner import parse_cron_line

        job = parse_cron_line(
            "PATH=/usr/local/sbin:/usr/bin",
            system_crontab=True
        )

        self.assertIsNone(job)

    def test_ignore_comment_and_blank_line(self):
        from modules.cron_scanner import parse_cron_line

        self.assertIsNone(
            parse_cron_line("# This is a comment")
        )

        self.assertIsNone(
            parse_cron_line("   ")
        )

    def test_parse_user_crontab_entry(self):
        from modules.cron_scanner import parse_cron_line

        job = parse_cron_line(
            "*/5 * * * * /usr/bin/example",
            system_crontab=False
        )

        self.assertEqual(job["schedule"], "*/5 * * * *")
        self.assertIsNone(job["username"])
        self.assertFalse(job["runs_as_root"])
        self.assertEqual(job["command"], "/usr/bin/example")


    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_secure_scheduled_script(self, mock_group, mock_owner):
        from modules.cron_scanner import inspect_scheduled_command

        os.chmod(self.test_file, 0o755)

        job = {
            "source": "/etc/crontab",
            "line_number": 1,
            "command": self.test_file,
            "runs_as_root": True,
        }

        result = inspect_scheduled_command(job)

        self.assertEqual(len(result["inspected_files"]), 1)
        self.assertEqual(result["findings"], [])

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_group_writable_scheduled_script(self, mock_group, mock_owner):
        from modules.cron_scanner import inspect_scheduled_command

        os.chmod(self.test_file, 0o664)

        job = {
            "command": self.test_file,
            "runs_as_root": True,
        }

        result = inspect_scheduled_command(job)

        self.assertTrue(
            any(
                finding["issue"] == "Referenced file is group-writable"
                for finding in result["findings"]
            )
        )

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_world_writable_scheduled_script(self, mock_group, mock_owner):
        from modules.cron_scanner import inspect_scheduled_command

        os.chmod(self.test_file, 0o666)

        job = {
            "command": self.test_file,
            "runs_as_root": True,
        }

        result = inspect_scheduled_command(job)

        self.assertTrue(
            any(
                finding["severity"] == "CRITICAL"
                and finding["issue"] == "Referenced file is world-writable"
                for finding in result["findings"]
            )
        )

    def test_non_root_scheduled_job_is_skipped(self):
        from modules.cron_scanner import inspect_scheduled_command

        job = {
            "command": self.test_file,
            "runs_as_root": False,
        }

        result = inspect_scheduled_command(job)

        self.assertEqual(result["inspected_files"], [])
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()

class TestPeriodicCronDirectoryScanner(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cron_dir = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_secure_executable_script_is_inspected(
        self, mock_group, mock_owner
    ):
        from modules.cron_scanner import scan_periodic_cron_directories

        script = os.path.join(self.cron_dir, "daily_job")

        with open(script, "w", encoding="utf-8") as file:
            file.write("#!/bin/sh\\n")

        os.chmod(script, 0o755)

        result = scan_periodic_cron_directories([self.cron_dir])

        self.assertEqual(len(result["scripts_inspected"]), 1)
        self.assertEqual(result["findings"], [])

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_group_writable_script_is_flagged(
        self, mock_group, mock_owner
    ):
        from modules.cron_scanner import scan_periodic_cron_directories

        script = os.path.join(self.cron_dir, "daily_job")

        with open(script, "w", encoding="utf-8") as file:
            file.write("#!/bin/sh\\n")

        os.chmod(script, 0o775)

        result = scan_periodic_cron_directories([self.cron_dir])

        self.assertTrue(
            any(
                finding["issue"] == "Group-writable cron file or directory"
                for finding in result["findings"]
            )
        )

    @patch("modules.cron_scanner.get_owner_name", return_value="root")
    @patch("modules.cron_scanner.get_group_name", return_value="root")
    def test_non_executable_file_is_ignored(
        self, mock_group, mock_owner
    ):
        from modules.cron_scanner import scan_periodic_cron_directories

        ordinary_file = os.path.join(self.cron_dir, "notes.txt")

        with open(ordinary_file, "w", encoding="utf-8") as file:
            file.write("Not a scheduled executable.\\n")

        os.chmod(ordinary_file, 0o644)

        result = scan_periodic_cron_directories([self.cron_dir])

        self.assertEqual(result["scripts_inspected"], [])
        self.assertEqual(result["findings"], [])
