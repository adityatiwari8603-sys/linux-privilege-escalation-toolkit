import unittest
from unittest.mock import patch, Mock
from subprocess import CompletedProcess, TimeoutExpired

from modules import kernel_checker


class TestReadOSRelease(unittest.TestCase):

    def test_reads_distribution_information(self):
        content = (
            'NAME="Kali GNU/Linux"\n'
            'ID=kali\n'
            'VERSION_ID="2026.3"\n'
        )

        with patch(
            "builtins.open",
            unittest.mock.mock_open(read_data=content)
        ):
            result, errors = kernel_checker.read_os_release()

        self.assertEqual(result["NAME"], "Kali GNU/Linux")
        self.assertEqual(result["ID"], "kali")
        self.assertEqual(result["VERSION_ID"], "2026.3")
        self.assertEqual(errors, [])

    def test_handles_missing_file(self):
        with patch(
            "builtins.open",
            side_effect=FileNotFoundError("File not found")
        ):
            result, errors = kernel_checker.read_os_release()

        self.assertEqual(result["NAME"], "Unknown")
        self.assertEqual(len(errors), 1)

    def test_ignores_comments_and_invalid_lines(self):
        content = (
            '# This is a comment\n'
            'NAME="Kali GNU/Linux"\n'
            'INVALID_LINE\n'
            'ID=kali\n'
        )

        with patch(
            "builtins.open",
            unittest.mock.mock_open(read_data=content)
        ):
            result, errors = kernel_checker.read_os_release()

        self.assertEqual(result["NAME"], "Kali GNU/Linux")
        self.assertEqual(result["ID"], "kali")
        self.assertNotIn("INVALID_LINE", result)
        self.assertEqual(errors, [])


class TestInstalledKernelPackages(unittest.TestCase):

    def test_handles_missing_dpkg_query(self):
        with patch.object(kernel_checker, "DPKG_QUERY", None):
            packages, errors = (
                kernel_checker.get_installed_kernel_packages()
            )

        self.assertEqual(packages, [])
        self.assertTrue(errors)

    def test_parses_installed_kernel_packages(self):
        output = (
            "linux-image-6.19.14+kali-amd64\t6.19.14-1kali1\n"
            "linux-image-7.1.5+kali-amd64\t7.1.5-1kali1\n"
        )

        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout=output,
            stderr=""
        )

        with patch.object(kernel_checker, "DPKG_QUERY", "/usr/bin/dpkg-query"):
            with patch(
                "modules.kernel_checker.subprocess.run",
                return_value=completed
            ):
                packages, errors = (
                    kernel_checker.get_installed_kernel_packages()
                )

        self.assertEqual(len(packages), 2)
        self.assertEqual(
            packages[0]["kernel_release"],
            "6.19.14+kali-amd64"
        )
        self.assertEqual(
            packages[1]["package_version"],
            "7.1.5-1kali1"
        )
        self.assertEqual(errors, [])

    def test_handles_query_timeout(self):
        with patch.object(kernel_checker, "DPKG_QUERY", "/usr/bin/dpkg-query"):
            with patch(
                "modules.kernel_checker.subprocess.run",
                side_effect=TimeoutExpired(cmd="dpkg-query", timeout=10)
            ):
                packages, errors = (
                    kernel_checker.get_installed_kernel_packages()
                )

        self.assertEqual(packages, [])
        self.assertIn("timed out", errors[0])

    def test_handles_query_os_error(self):
        with patch.object(kernel_checker, "DPKG_QUERY", "/usr/bin/dpkg-query"):
            with patch(
                "modules.kernel_checker.subprocess.run",
                side_effect=OSError("Permission denied")
            ):
                packages, errors = (
                    kernel_checker.get_installed_kernel_packages()
                )

        self.assertEqual(packages, [])
        self.assertIn("Permission denied", errors[0])


class TestCollectKernelInfo(unittest.TestCase):

    def test_collects_kernel_information(self):
        distribution = {
            "PRETTY_NAME": "Kali GNU/Linux Rolling",
            "ID": "kali",
            "VERSION_ID": "2026.3"
        }

        installed = [
            {
                "package": "linux-image-7.1.5+kali-amd64",
                "package_version": "7.1.5-1kali1",
                "kernel_release": "7.1.5+kali-amd64"
            }
        ]

        with patch(
            "modules.kernel_checker.read_os_release",
            return_value=(distribution, [])
        ):
            with patch(
                "modules.kernel_checker.get_installed_kernel_packages",
                return_value=(installed, [])
            ):
                with patch(
                    "modules.kernel_checker.platform.release",
                    return_value="7.1.5+kali-amd64"
                ):
                    with patch(
                        "modules.kernel_checker.platform.machine",
                        return_value="x86_64"
                    ):
                        result = kernel_checker.collect_kernel_info()

        self.assertEqual(
            result["distribution"],
            "Kali GNU/Linux Rolling"
        )
        self.assertEqual(result["distribution_id"], "kali")
        self.assertEqual(result["distribution_version"], "2026.3")
        self.assertEqual(result["running_kernel"], "7.1.5+kali-amd64")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertTrue(result["running_kernel_installed"])
        self.assertEqual(result["errors"], [])

    def test_collects_errors_from_sources(self):
        with patch(
            "modules.kernel_checker.read_os_release",
            return_value=({"NAME": "Unknown"}, ["OS release unavailable"])
        ):
            with patch(
                "modules.kernel_checker.get_installed_kernel_packages",
                return_value=([], ["Package query failed"])
            ):
                with patch(
                    "modules.kernel_checker.platform.release",
                    return_value="7.1.5+kali-amd64"
                ):
                    with patch(
                        "modules.kernel_checker.platform.machine",
                        return_value="x86_64"
                    ):
                        result = kernel_checker.collect_kernel_info()

        self.assertEqual(len(result["errors"]), 2)
        self.assertIsNone(result["running_kernel_installed"])


class TestKernelAnalysis(unittest.TestCase):

    def test_detects_kernel_mismatch(self):
        information = {
            "running_kernel": "7.1.5+kali-amd64",
            "installed_kernels": [
                {
                    "kernel_release": "6.19.14+kali-amd64"
                }
            ],
            "running_kernel_installed": False
        }

        findings = kernel_checker.analyze_kernel_info(information)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertIn("does not match", findings[0]["issue"])

    def test_detects_empty_kernel_inventory(self):
        information = {
            "running_kernel": "7.1.5+kali-amd64",
            "installed_kernels": [],
            "running_kernel_installed": None
        }

        findings = kernel_checker.analyze_kernel_info(information)

        self.assertEqual(len(findings), 1)
        self.assertIn("inventory is unavailable", findings[0]["issue"])

    def test_returns_no_findings_when_kernel_matches(self):
        information = {
            "running_kernel": "7.1.5+kali-amd64",
            "installed_kernels": [
                {
                    "kernel_release": "7.1.5+kali-amd64"
                }
            ],
            "running_kernel_installed": True
        }

        findings = kernel_checker.analyze_kernel_info(information)

        self.assertEqual(findings, [])


class TestKernelScanner(unittest.TestCase):

    def test_scan_kernel_returns_expected_structure(self):
        information = {
            "distribution": "Kali GNU/Linux",
            "distribution_id": "kali",
            "distribution_version": "2026.3",
            "running_kernel": "7.1.5+kali-amd64",
            "architecture": "x86_64",
            "installed_kernels": [],
            "running_kernel_installed": None,
            "errors": []
        }

        with patch(
            "modules.kernel_checker.collect_kernel_info",
            return_value=information
        ):
            results = kernel_checker.scan_kernel()

        self.assertIn("kernel_info", results)
        self.assertIn("findings", results)
        self.assertIn("errors", results)
        self.assertEqual(len(results["findings"]), 1)


class TestDisplayResults(unittest.TestCase):

    def test_displays_kernel_information(self):
        results = {
            "kernel_info": {
                "distribution": "Kali GNU/Linux",
                "distribution_id": "kali",
                "distribution_version": "2026.3",
                "running_kernel": "7.1.5+kali-amd64",
                "architecture": "x86_64",
                "installed_kernels": [],
                "running_kernel_installed": None,
                "errors": []
            },
            "findings": [],
            "errors": []
        }

        with patch("builtins.print") as mock_print:
            kernel_checker.display_results(results)

        printed_output = " ".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("LINUX KERNEL SECURITY AUDIT", printed_output)
        self.assertIn("7.1.5+kali-amd64", printed_output)


if __name__ == "__main__":
    unittest.main()
