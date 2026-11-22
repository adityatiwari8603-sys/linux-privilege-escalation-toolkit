"""
Linux Capabilities Security Scanner.

Detection-only scanner that discovers files with Linux capabilities
and performs contextual security checks.

This module never modifies capabilities or executes discovered files.
"""

import os
import pwd
import grp
import shutil
import stat
import subprocess


GETCAP = shutil.which("getcap")

DEFAULT_SCAN_PATHS = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
]

# Capabilities that deserve contextual security review.
HIGH_RISK_CAPABILITIES = {
    "cap_sys_admin",
    "cap_sys_module",
    "cap_sys_ptrace",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_setuid",
    "cap_setgid",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_mknod",
}


def get_owner_name(uid):
    """Resolve a numeric UID to a username."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def get_group_name(gid):
    """Resolve a numeric GID to a group name."""
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def parse_capability_line(line):
    """
    Parse one getcap output line.

    Example:
    /usr/bin/dumpcap cap_net_admin,cap_net_raw=eip
    """

    line = line.strip()

    if not line:
        return None

    parts = line.rsplit(maxsplit=1)

    if len(parts) != 2:
        return None

    path, capability_expression = parts

    if "=" not in capability_expression:
        return None

    capability_names, flags = capability_expression.rsplit("=", 1)

    capabilities = [
        capability.strip().lower()
        for capability in capability_names.split(",")
        if capability.strip()
    ]

    if not capabilities:
        return None

    return {
        "path": path,
        "capabilities": capabilities,
        "flags": flags,
        "raw": line,
    }


def inspect_file(path):
    """Inspect file ownership and permissions without modifying it."""

    try:
        file_stat = os.stat(path, follow_symlinks=False)

        mode = file_stat.st_mode

        return {
            "path": path,
            "exists": True,
            "owner": get_owner_name(file_stat.st_uid),
            "group": get_group_name(file_stat.st_gid),
            "permissions": oct(stat.S_IMODE(mode)),
            "is_regular_file": stat.S_ISREG(mode),
            "is_symlink": stat.S_ISLNK(
                os.lstat(path).st_mode
            ),
            "world_writable": bool(mode & stat.S_IWOTH),
            "group_writable": bool(mode & stat.S_IWGRP),
            "error": None,
        }

    except OSError as exc:
        return {
            "path": path,
            "exists": False,
            "error": str(exc),
        }


def analyze_capabilities(parsed, file_info):
    """Generate contextual findings from capability information."""

    findings = []

    path = parsed["path"]
    capabilities = parsed["capabilities"]

    risky = HIGH_RISK_CAPABILITIES.intersection(capabilities)

    if risky:
        findings.append({
            "severity": "HIGH",
            "issue": "High-risk Linux capability assigned",
            "path": path,
            "evidence": sorted(risky),
            "recommendation": (
                "Review whether this executable requires these "
                "capabilities and whether access is appropriately restricted."
            ),
        })

    if file_info.get("world_writable"):
        findings.append({
            "severity": "CRITICAL",
            "issue": "Capability-enabled file is world-writable",
            "path": path,
            "evidence": "World-write permission is enabled.",
            "recommendation": (
                "Investigate the file ownership and permissions "
                "through an authorized administrative review."
            ),
        })

    elif file_info.get("group_writable"):
        findings.append({
            "severity": "HIGH",
            "issue": "Capability-enabled file is group-writable",
            "path": path,
            "evidence": "Group-write permission is enabled.",
            "recommendation": (
                "Review group membership and whether the group "
                "should be allowed to modify this executable."
            ),
        })

    return findings


def scan_capabilities(scan_paths=None, timeout=60):
    """
    Discover and inspect Linux file capabilities.

    Uses getcap in recursive read-only mode.
    """

    if scan_paths is None:
        scan_paths = DEFAULT_SCAN_PATHS

    result = {
        "scanner": "Linux Capabilities Security Scanner",
        "files_scanned": 0,
        "capability_files_found": 0,
        "findings": [],
        "observations": [],
        "errors": [],
    }

    if not GETCAP:
        result["errors"].append(
            "getcap utility is not installed or not available in PATH."
        )
        return result

    valid_paths = [
        path for path in scan_paths
        if os.path.exists(path)
    ]

    if not valid_paths:
        result["errors"].append(
            "No valid scan directories were provided."
        )
        return result

    try:
        process = subprocess.run(
            [GETCAP, "-r", *valid_paths],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired:
        result["errors"].append(
            "Capability scan timed out."
        )
        return result

    except OSError as exc:
        result["errors"].append(str(exc))
        return result

    if process.returncode not in (0, 1):
        result["errors"].append(
            process.stderr.strip() or
            f"getcap exited with status {process.returncode}"
        )

    for line in process.stdout.splitlines():

        parsed = parse_capability_line(line)

        if not parsed:
            continue

        result["files_scanned"] += 1
        result["capability_files_found"] += 1

        file_info = inspect_file(parsed["path"])

        observation = {
            **parsed,
            "file_info": file_info,
        }

        result["observations"].append(observation)

        result["findings"].extend(
            analyze_capabilities(parsed, file_info)
        )

    if process.stderr.strip():
        result["errors"].append(process.stderr.strip())

    return result


def display_results(result):
    """Display capability scanner results."""

    print("\n" + "=" * 65)
    print("LINUX CAPABILITIES SECURITY SCANNER")
    print("=" * 65)

    print(f"Capability-enabled files: {result['capability_files_found']}")
    print(f"Findings: {len(result['findings'])}")

    for observation in result["observations"]:

        print("\nFile:", observation["path"])

        print(
            "Capabilities:",
            ", ".join(observation["capabilities"])
        )

        print("Flags:", observation["flags"])

        file_info = observation["file_info"]

        if file_info.get("error"):
            print("Inspection error:", file_info["error"])
        else:
            print("Owner:", file_info["owner"])
            print("Group:", file_info["group"])
            print("Permissions:", file_info["permissions"])

    print("\nSECURITY FINDINGS")

    for finding in result["findings"]:
        print(f"\n[{finding['severity']}] {finding['issue']}")
        print("Path:", finding["path"])
        print("Evidence:", finding["evidence"])
        print("Recommendation:", finding["recommendation"])

    if not result["findings"]:
        print("No contextual security findings detected.")

    if result["errors"]:
        print("\nSCAN ERRORS")

        for error in result["errors"]:
            print("-", error)
