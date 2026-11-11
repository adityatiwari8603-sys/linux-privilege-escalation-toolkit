import os
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from modules.sudo_analyzer import (
    inspect_sudoers_file,
    analyze_sudoers_rules,
    check_current_user_sudo
)


class TestInspectSudoersFile(unittest.TestCase):

    @patch("modules.sudo_analyzer.os.stat")
    def test_secure_sudoers_file(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o440,
            st_uid=0,
            st_gid=0
        )

        result = inspect_sudoers_file("/fake/sudoers")

        self.assertTrue(result["exists"])
        self.assertEqual(result["permissions"], "0o440")
        self.assertEqual(len(result["findings"]), 0)

    @patch("modules.sudo_analyzer.os.stat")
    def test_non_root_owner(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o440,
            st_uid=1000,
            st_gid=1000
        )

        result = inspect_sudoers_file("/fake/sudoers")

        self.assertTrue(
            any("not owned by root" in f["issue"]
                for f in result["findings"])
        )

    @patch("modules.sudo_analyzer.os.stat")
    def test_group_writable_file(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o460,
            st_uid=0,
            st_gid=0
        )

        result = inspect_sudoers_file("/fake/sudoers")

        self.assertTrue(
            any(f["severity"] == "CRITICAL"
                for f in result["findings"])
        )

    @patch("modules.sudo_analyzer.os.stat")
    def test_world_readable_file(self, mock_stat):
        mock_stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_uid=0,
            st_gid=0
        )

        result = inspect_sudoers_file("/fake/sudoers")

        self.assertTrue(
            any(f["severity"] == "LOW"
                for f in result["findings"])
        )

    def test_missing_file(self):
        result = inspect_sudoers_file(
            "/this/path/does/not/exist/sudoers"
        )

        self.assertFalse(result["exists"])
        self.assertEqual(result["findings"], [])

    @patch("modules.sudo_analyzer.os.stat")
    def test_permission_denied(self, mock_stat):
        mock_stat.side_effect = PermissionError

        result = inspect_sudoers_file("/fake/sudoers")

        self.assertTrue(
            any("Permission denied" in f["issue"]
                for f in result["findings"])
        )


class TestSudoersRuleAnalysis(unittest.TestCase):

    def test_detect_nopasswd_rule(self):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as temp_file:
            temp_file.write(
                "kali ALL=(ALL) NOPASSWD: /usr/bin/example\n"
            )
            path = temp_file.name

        try:
            result = analyze_sudoers_rules([path])

            self.assertEqual(result["files_checked"], 1)
            self.assertEqual(result["total_findings"], 1)
            self.assertEqual(
                result["findings"][0]["severity"], "HIGH"
            )
        finally:
            os.unlink(path)

    def test_detect_broad_sudo_rule(self):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as temp_file:
            temp_file.write(
                "kali ALL=(ALL : ALL) ALL\n"
            )
            path = temp_file.name

        try:
            result = analyze_sudoers_rules([path])

            self.assertEqual(result["total_findings"], 1)
            self.assertEqual(
                result["findings"][0]["severity"], "MEDIUM"
            )
        finally:
            os.unlink(path)

    def test_restricted_rule_has_no_finding(self):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as temp_file:
            temp_file.write(
                "kali ALL=(root) /usr/bin/systemctl status\n"
            )
            path = temp_file.name

        try:
            result = analyze_sudoers_rules([path])

            self.assertEqual(result["total_findings"], 0)
        finally:
            os.unlink(path)

    def test_missing_sudoers_file(self):
        result = analyze_sudoers_rules(
            ["/missing/test/sudoers"]
        )

        self.assertEqual(result["files_checked"], 0)
        self.assertTrue(result["errors"])


class TestCurrentUserSudo(unittest.TestCase):

    @patch("modules.sudo_analyzer.subprocess.run")
    def test_successful_sudo_query(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            stdout="User kali may run the following commands",
            stderr="",
            returncode=0
        )

        result = check_current_user_sudo()

        self.assertEqual(result["status"], "success")
        self.assertIn("User kali", result["output"])

    @patch("modules.sudo_analyzer.subprocess.run")
    def test_authentication_required(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            stdout="",
            stderr="sudo: a password is required",
            returncode=1
        )

        result = check_current_user_sudo()

        self.assertEqual(
            result["status"], "authentication_required"
        )

    @patch("modules.sudo_analyzer.subprocess.run")
    def test_sudo_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sudo", "-n", "-l"],
            timeout=10
        )

        result = check_current_user_sudo()

        self.assertEqual(result["status"], "timeout")

    @patch("modules.sudo_analyzer.subprocess.run")
    def test_sudo_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError

        result = check_current_user_sudo()

        self.assertEqual(result["status"], "sudo_not_found")


if __name__ == "__main__":
    unittest.main()
