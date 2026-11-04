import unittest

from modules.system_info import collect_system_info


class TestSystemInfo(unittest.TestCase):

    def setUp(self):
        self.info = collect_system_info()

    def test_returns_dictionary(self):
        self.assertIsInstance(self.info, dict)

    def test_required_fields_exist(self):
        required_fields = [
            "hostname",
            "operating_system",
            "distribution",
            "kernel_version",
            "architecture",
            "username",
            "uid",
            "gid",
            "groups",
            "home_directory",
            "collection_time"
        ]

        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, self.info)

    def test_uid_is_integer(self):
        self.assertIsInstance(self.info["uid"], int)

    def test_groups_is_list(self):
        self.assertIsInstance(self.info["groups"], list)

    def test_hostname_is_not_empty(self):
        self.assertTrue(self.info["hostname"])

    def test_username_is_not_empty(self):
        self.assertTrue(self.info["username"])


if __name__ == "__main__":
    unittest.main()
