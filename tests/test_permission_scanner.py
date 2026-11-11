import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from modules.permission_scanner import check_file_permissions


class TestPermissionScanner(unittest.TestCase):

    def test_world_writable_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "test.txt")

            with open(path, "w") as file:
                file.write("test")

            os.chmod(path, 0o666)

            result = check_file_permissions(path, os.stat(path))

            self.assertTrue(any(
                item["severity"] == "HIGH"
                for item in result
            ))

    def test_world_writable_directory_without_sticky_bit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "unsafe")

            os.mkdir(path)
            os.chmod(path, 0o777)

            result = check_file_permissions(path, os.stat(path))

            self.assertTrue(any(
                item["severity"] == "HIGH"
                for item in result
            ))

    def test_world_writable_directory_with_sticky_bit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "sticky")

            os.mkdir(path)
            os.chmod(path, 0o1777)

            result = check_file_permissions(path, os.stat(path))

            self.assertTrue(any(
                item["severity"] == "LOW"
                for item in result
            ))

    def test_secure_sensitive_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "shadow")

            with open(path, "w") as file:
                file.write("test")

            os.chmod(path, 0o640)

            with patch(
                "modules.permission_scanner.SENSITIVE_FILE_POLICIES",
                {
                    path: {
                        "group": "shadow",
                        "world_read": False
                    }
                }
            ), patch(
                "modules.permission_scanner.get_owner_name",
                return_value="root"
            ), patch(
                "modules.permission_scanner.get_group_name",
                return_value="shadow"
            ):

                result = check_file_permissions(path, os.stat(path))

                self.assertEqual(result, [])

    def test_group_writable_sensitive_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "shadow")

            with open(path, "w") as file:
                file.write("test")

            os.chmod(path, 0o660)

            with patch(
                "modules.permission_scanner.SENSITIVE_FILE_POLICIES",
                {
                    path: {
                        "group": "shadow",
                        "world_read": False
                    }
                }
            ), patch(
                "modules.permission_scanner.get_owner_name",
                return_value="root"
            ), patch(
                "modules.permission_scanner.get_group_name",
                return_value="shadow"
            ):

                result = check_file_permissions(path, os.stat(path))

                self.assertTrue(any(
                    item["severity"] == "CRITICAL"
                    for item in result
                ))

    def test_private_key_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "id_rsa")

            with open(path, "w") as file:
                file.write("test")

            os.chmod(path, 0o644)

            result = check_file_permissions(path, os.stat(path))

            self.assertTrue(any(
                item["issue"] == "Private key permissions"
                for item in result
            ))

    def test_normal_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "normal.txt")

            with open(path, "w") as file:
                file.write("test")

            os.chmod(path, 0o644)

            result = check_file_permissions(path, os.stat(path))

            self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
