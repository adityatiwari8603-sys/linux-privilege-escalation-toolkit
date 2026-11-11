"""
Sudo Permissions Analyzer

Detection-only module for identifying potentially risky sudo
permissions and sudoers configuration file permissions.

This module never executes privileged commands.
"""

import os
import re
import pwd
import grp
import stat
import subprocess


SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"


def get_owner_name(uid):
    """Return the username associated with a UID."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def get_group_name(gid):
    """Return the group name associated with a GID."""
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def inspect_sudoers_file(path):
    """Check ownership and permissions of a sudoers configuration file."""

    result = {
        "path": path,
        "exists": False,
        "owner": None,
        "group": None,
        "permissions": None,
        "findings": []
    }

    try:
        file_stat = os.stat(path, follow_symlinks=False)

        if not stat.S_ISREG(file_stat.st_mode):
            return result

        result["exists"] = True
        result["owner"] = get_owner_name(file_stat.st_uid)
        result["group"] = get_group_name(file_stat.st_gid)
        result["permissions"] = oct(
            stat.S_IMODE(file_stat.st_mode)
        )

        if file_stat.st_uid != 0:
            result["findings"].append({
                "severity": "HIGH",
                "issue": "Sudoers file is not owned by root",
                "evidence": f"Owner: {result['owner']}"
            })

        if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            result["findings"].append({
                "severity": "CRITICAL",
                "issue": "Sudoers file is group-writable or world-writable",
                "evidence": f"Permissions: {result['permissions']}"
            })

        if file_stat.st_mode & stat.S_IROTH:
            result["findings"].append({
                "severity": "LOW",
                "issue": "Sudoers file is world-readable",
                "evidence": f"Permissions: {result['permissions']}"
            })

    except FileNotFoundError:
        pass
    except PermissionError:
        result["findings"].append({
            "severity": "INFO",
            "issue": "Permission denied while inspecting file",
            "evidence": path
        })
    except OSError as error:
        result["findings"].append({
            "severity": "INFO",
            "issue": "Unable to inspect sudoers file",
            "evidence": str(error)
        })

    return result


def get_sudoers_files():
    """Return the main sudoers file and regular drop-in files."""

    paths = [SUDOERS_FILE]

    try:
        with os.scandir(SUDOERS_DIR) as entries:
            for entry in entries:
                if entry.is_file(follow_symlinks=False):
                    paths.append(entry.path)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    except OSError:
        pass

    return paths


def analyze_sudoers_rules(paths=None):
    """
    Perform conservative text-based checks on sudoers files.

    This is not a complete sudoers parser. Aliases, continuations,
    includes, negations, and complex rule semantics need additional
    interpretation.
    """

    if paths is None:
        paths = get_sudoers_files()

    findings = []
    files_checked = 0
    errors = []

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as file:
                files_checked += 1

                for line_number, original_line in enumerate(file, start=1):
                    line = original_line.split("#", 1)[0].strip()

                    if not line or line.startswith("@include"):
                        continue

                    if re.search(r"\bNOPASSWD\s*:", line, re.IGNORECASE):
                        findings.append({
                            "severity": "HIGH",
                            "issue": "NOPASSWD sudo rule detected",
                            "file": path,
                            "line": line_number,
                            "evidence": line
                        })

                    if re.search(
                        r"=\s*\(\s*ALL(?:\s*:\s*ALL)?\s*\)\s*ALL\b",
                        line,
                        re.IGNORECASE
                    ):
                        findings.append({
                            "severity": "MEDIUM",
                            "issue": "Potentially broad sudo permission detected",
                            "file": path,
                            "line": line_number,
                            "evidence": line
                        })

        except FileNotFoundError:
            errors.append(f"File not found: {path}")
        except PermissionError:
            errors.append(f"Permission denied: {path}")
        except OSError as error:
            errors.append(f"{path}: {error}")

    return {
        "files_checked": files_checked,
        "total_findings": len(findings),
        "findings": findings,
        "errors": errors
    }


def check_current_user_sudo():
    """
    Query the current user's sudo privileges without prompting
    for a password or executing privileged commands.
    """

    try:
        result = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        output = (result.stdout + "\n" + result.stderr).strip()

        if "a password is required" in output.lower():
            status = "authentication_required"
        elif result.returncode == 0:
            status = "success"
        else:
            status = "query_failed"

        return {
            "status": status,
            "return_code": result.returncode,
            "output": output
        }

    except FileNotFoundError:
        return {
            "status": "sudo_not_found",
            "return_code": None,
            "output": "sudo command was not found."
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "return_code": None,
            "output": "Sudo permission query timed out."
        }
    except OSError as error:
        return {
            "status": "error",
            "return_code": None,
            "output": str(error)
        }


def scan_sudo_permissions():
    """Run the complete sudo permissions audit."""

    file_results = [
        inspect_sudoers_file(path)
        for path in get_sudoers_files()
    ]

    query = check_current_user_sudo()
    rule_results = analyze_sudoers_rules()

    # Analyze effective permissions returned by sudo -l.
    effective_findings = []

    if query["status"] == "success":
        for line_number, line in enumerate(
            query["output"].splitlines(), start=1
        ):
            line = line.strip()

            if not line:
                continue

            if re.search(r"\bNOPASSWD\s*:", line, re.IGNORECASE):
                effective_findings.append({
                    "severity": "HIGH",
                    "issue": "NOPASSWD sudo permission detected",
                    "file": "Effective sudo permission listing",
                    "line": line_number,
                    "evidence": line
                })

            if re.search(
                r"^\(ALL(?:\s*:\s*ALL)?\)\s+ALL\b",
                line,
                re.IGNORECASE
            ):
                effective_findings.append({
                    "severity": "MEDIUM",
                    "issue": "Broad administrative sudo permission detected",
                    "file": "Effective sudo permission listing",
                    "line": line_number,
                    "evidence": line
                })

    rule_results["findings"].extend(effective_findings)
    rule_results["total_findings"] = len(rule_results["findings"])

    file_findings = []

    for file_result in file_results:
        for finding in file_result["findings"]:
            file_findings.append({
                **finding,
                "file": file_result["path"]
            })

    return {
        "sudo_query": query,
        "sudoers_files": file_results,
        "rule_analysis": rule_results,
        "file_findings": file_findings
    }


def display_results(results):
    """Display sudo audit results in the terminal."""

    print("\n" + "=" * 65)
    print("       LINUX SUDO PERMISSIONS SECURITY ANALYZER")
    print("=" * 65)

    query = results["sudo_query"]

    print("\n[1] Current User Sudo Query")
    print(f"Status: {query['status']}")

    if query["output"]:
        print(f"Output: {query['output']}")

    print("\n[2] Sudoers File Inspection")

    for file_result in results["sudoers_files"]:
        print(f"\nFile: {file_result['path']}")

        if file_result["exists"]:
            print(f"Owner: {file_result['owner']}")
            print(f"Group: {file_result['group']}")
            print(f"Permissions: {file_result['permissions']}")
        else:
            print("File unavailable or not a regular file.")

    print("\n[3] Sudo Rule Analysis")

    rule_results = results["rule_analysis"]

    print(f"Files checked: {rule_results['files_checked']}")
    print(f"Rule findings: {rule_results['total_findings']}")

    for finding in rule_results["findings"]:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Issue: {finding['issue']}")
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Evidence: {finding['evidence']}")

    print("\n[4] Sudoers File Permission Findings")

    if not results["file_findings"]:
        print("No file permission findings detected.")

    for finding in results["file_findings"]:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Issue: {finding['issue']}")
        print(f"File: {finding['file']}")

    if rule_results["errors"]:
        print("\n[5] Inspection Errors")

        for error in rule_results["errors"]:
            print(error)

    print("\n" + "=" * 65)
    print("Sudo audit completed. Detection only; no privileged commands executed.")
    print("=" * 65)


if __name__ == "__main__":
    results = scan_sudo_permissions()
    display_results(results)
