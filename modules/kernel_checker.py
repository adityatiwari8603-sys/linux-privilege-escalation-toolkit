"""
Linux Kernel Security Checker

Read-only inventory and consistency checks for Linux kernels.

This module does not exploit vulnerabilities, modify kernel settings,
install packages, or reboot the system.
"""

import platform
import shutil
import subprocess
from pathlib import Path


DPKG_QUERY = shutil.which("dpkg-query")


def read_os_release(path="/etc/os-release"):
    """Read Linux distribution information."""

    distribution = {}

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                distribution[key] = value.strip().strip('"').strip("'")

    except OSError as error:
        return {"NAME": "Unknown"}, [str(error)]

    return distribution, []


def get_installed_kernel_packages():
    """
    Discover installed Linux kernel packages using dpkg-query.

    This function is intended for Debian-based distributions.
    It never installs, removes, or modifies packages.
    """

    if not DPKG_QUERY:
        return [], ["dpkg-query utility is unavailable"]

    try:
        result = subprocess.run(
            [
                DPKG_QUERY,
                "-W",
                "-f=${binary:Package}\t${Version}\n",
                "linux-image-[0-9]*",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0 and not result.stdout.strip():
            return [], [
                result.stderr.strip() or "Unable to query installed kernel packages"
            ]

        packages = []

        for line in result.stdout.splitlines():
            parts = line.split("\t", 1)

            if len(parts) != 2:
                continue

            package_name = parts[0].strip().split(":", 1)[0]
            package_version = parts[1].strip()

            prefix = "linux-image-"

            if not package_name.startswith(prefix):
                continue

            kernel_release = package_name[len(prefix):]

            packages.append({
                "package": package_name,
                "package_version": package_version,
                "kernel_release": kernel_release,
            })

        return packages, []

    except subprocess.TimeoutExpired:
        return [], ["Kernel package query timed out"]

    except OSError as error:
        return [], [str(error)]


def collect_kernel_info():
    """Collect kernel, distribution and installed package information."""

    distribution, errors = read_os_release()

    installed_kernels, package_errors = (
        get_installed_kernel_packages()
    )

    errors.extend(package_errors)

    running_kernel = platform.release()

    installed_releases = [
        item["kernel_release"]
        for item in installed_kernels
    ]

    running_kernel_installed = (
        running_kernel in installed_releases
        if installed_kernels
        else None
    )

    return {
        "distribution": distribution.get("PRETTY_NAME", "Unknown"),
        "distribution_id": distribution.get("ID", "unknown"),
        "distribution_version": distribution.get("VERSION_ID", "unknown"),
        "running_kernel": running_kernel,
        "architecture": platform.machine(),
        "installed_kernels": installed_kernels,
        "running_kernel_installed": running_kernel_installed,
        "errors": errors,
    }


def analyze_kernel_info(kernel_info):
    """Generate evidence-based informational observations."""

    findings = []

    if kernel_info["running_kernel_installed"] is False:
        findings.append({
            "severity": "INFO",
            "issue": "Running kernel does not match a discovered installed kernel package",
            "evidence": kernel_info["running_kernel"],
            "recommendation": (
                "Review installed kernel packages and determine whether "
                "a newer kernel requires activation through a planned reboot."
            ),
        })

    if not kernel_info["installed_kernels"]:
        findings.append({
            "severity": "INFO",
            "issue": "Installed kernel package inventory is unavailable",
            "evidence": "No installed kernel packages were discovered",
            "recommendation": (
                "Verify kernel inventory using the distribution's package manager."
            ),
        })

    return findings


def scan_kernel():
    """Run the read-only kernel security inventory."""

    kernel_info = collect_kernel_info()

    return {
        "kernel_info": kernel_info,
        "findings": analyze_kernel_info(kernel_info),
        "errors": kernel_info["errors"],
    }


def display_results(results):
    """Display kernel security information."""

    information = results["kernel_info"]

    print("\n" + "=" * 65)
    print("          LINUX KERNEL SECURITY AUDIT")
    print("=" * 65)

    print(f"Distribution       : {information['distribution']}")
    print(f"Distribution ID    : {information['distribution_id']}")
    print(f"Distribution Ver.  : {information['distribution_version']}")
    print(f"Running Kernel     : {information['running_kernel']}")
    print(f"Architecture       : {information['architecture']}")

    print("\nInstalled Kernels:")

    for kernel in information["installed_kernels"]:
        print(
            f"  {kernel['kernel_release']} "
            f"(package version: {kernel['package_version']})"
        )

    print(
        "\nRunning kernel matches installed package:",
        information["running_kernel_installed"],
    )

    print("\nObservations:")

    if results["findings"]:
        for finding in results["findings"]:
            print(
                f"[{finding['severity']}] "
                f"{finding['issue']}"
            )
            print(f"Evidence: {finding['evidence']}")
            print(f"Recommendation: {finding['recommendation']}")
    else:
        print("No kernel inventory consistency issues detected.")

    if results["errors"]:
        print("\nErrors:")

        for error in results["errors"]:
            print(f"  - {error}")

    print("=" * 65)


if __name__ == "__main__":
    results = scan_kernel()
    display_results(results)
