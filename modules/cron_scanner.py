"""
Cron Jobs Security Scanner

Detection-only module for identifying potentially insecure
Linux cron configurations and scheduled scripts.

This module never executes cron jobs or modifies system files.
"""

import os
import stat
import pwd
import grp
import subprocess
import re

DEFAULT_CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.yearly",
]

SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


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


def inspect_cron_file(path):
    """
    Inspect cron file metadata without executing or modifying it.

    Returns ownership, permissions and potential security issues.
    """
    result = {
        "path": path,
        "exists": False,
        "owner": None,
        "group": None,
        "permissions": None,
        "is_directory": False,
        "issues": [],
        "errors": [],
    }

    try:
        file_stat = os.stat(path, follow_symlinks=False)

        result["exists"] = True
        result["owner"] = get_owner_name(file_stat.st_uid)
        result["group"] = get_group_name(file_stat.st_gid)
        result["permissions"] = oct(
            stat.S_IMODE(file_stat.st_mode)
        )
        result["is_directory"] = stat.S_ISDIR(file_stat.st_mode)

        mode = file_stat.st_mode

        if result["owner"] != "root":
            result["issues"].append({
                "severity": "HIGH",
                "issue": "Cron configuration is not owned by root",
                "path": path,
            })

        if mode & stat.S_IWGRP:
            result["issues"].append({
                "severity": "HIGH",
                "issue": "Group-writable cron file or directory",
                "path": path,
            })

        if mode & stat.S_IWOTH:
            result["issues"].append({
                "severity": "CRITICAL",
                "issue": "World-writable cron file or directory",
                "path": path,
            })

    except FileNotFoundError:
        result["errors"].append("File or directory not found")

    except PermissionError:
        result["errors"].append("Permission denied")

    except OSError as error:
        result["errors"].append(str(error))

    return result


def parse_cron_line(line, source="<unknown>", line_number=0,
                    system_crontab=True):
    """
    Parse one cron configuration line.

    System cron format:
        minute hour day month weekday username command

    User crontab format:
        minute hour day month weekday command

    Returns a dictionary for valid job entries, otherwise None.
    Does not execute commands.
    """
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    # Ignore standalone environment assignments such as PATH=/usr/bin.
    # Do not skip cron jobs merely because their command contains NAME=value.
    first_token = line.split()[0]

    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", first_token):
        return None

    fields = line.split(None, 6 if system_crontab else 5)

    if fields[0].startswith("@"):
        if system_crontab:
            if len(fields) < 3:
                return None
            schedule = fields[0]
            username = fields[1]
            command = fields[2]
        else:
            if len(fields) < 2:
                return None
            schedule = fields[0]
            username = None
            command = fields[1]

    else:
        required_fields = 7 if system_crontab else 6

        if len(fields) < required_fields:
            return None

        schedule = " ".join(fields[:5])

        if system_crontab:
            username = fields[5]
            command = fields[6]
        else:
            username = None
            command = fields[5]

    return {
        "source": source,
        "line_number": line_number,
        "schedule": schedule,
        "username": username,
        "command": command,
        "runs_as_root": username == "root" if system_crontab else False,
    }


def parse_cron_file(path, system_crontab=True):
    """
    Read and parse cron entries from a file.

    Returns parsed jobs and any read errors.
    """
    result = {
        "path": path,
        "jobs": [],
        "errors": [],
    }

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            for line_number, line in enumerate(file, start=1):
                job = parse_cron_line(
                    line,
                    source=path,
                    line_number=line_number,
                    system_crontab=system_crontab,
                )

                if job is not None:
                    result["jobs"].append(job)

    except FileNotFoundError:
        result["errors"].append("Cron file not found")
    except PermissionError:
        result["errors"].append("Permission denied")
    except OSError as error:
        result["errors"].append(str(error))

    return result


def extract_absolute_paths(command):
    """
    Extract existing absolute-path candidates from a cron command.

    This is a heuristic: a path may be an argument rather than
    an executable. No discovered path is executed.
    """
    import re

    candidates = re.findall(
        r"(?<![A-Za-z0-9_])(/[A-Za-z0-9_./-]+)",
        command
    )

    paths = []

    for candidate in candidates:
        candidate = candidate.rstrip(".,;:)")
        if candidate != "/" and candidate not in paths:
            paths.append(candidate)

    return paths


def inspect_scheduled_command(job):
    """
    Inspect regular files referenced by a scheduled command.

    Findings are generated only for root-scheduled jobs.
    Symlinks and non-regular files are skipped.

    This function never executes or modifies referenced files.
    """
    result = {
        "source": job.get("source"),
        "line_number": job.get("line_number"),
        "command": job.get("command", ""),
        "runs_as_root": job.get("runs_as_root", False),
        "inspected_files": [],
        "findings": [],
        "errors": [],
    }

    if not result["runs_as_root"]:
        return result

    for file_path in extract_absolute_paths(result["command"]):
        try:
            file_stat = os.stat(file_path, follow_symlinks=False)

            if not stat.S_ISREG(file_stat.st_mode):
                continue

            owner = get_owner_name(file_stat.st_uid)
            group = get_group_name(file_stat.st_gid)
            permissions = stat.S_IMODE(file_stat.st_mode)

            file_info = {
                "path": file_path,
                "owner": owner,
                "group": group,
                "permissions": oct(permissions),
            }

            result["inspected_files"].append(file_info)

            if owner != "root":
                result["findings"].append({
                    "severity": "HIGH",
                    "issue": "Root-scheduled command references a non-root-owned file",
                    "path": file_path,
                    "owner": owner,
                })

            if permissions & stat.S_IWGRP:
                result["findings"].append({
                    "severity": "HIGH",
                    "issue": "Referenced file is group-writable",
                    "path": file_path,
                })

            if permissions & stat.S_IWOTH:
                result["findings"].append({
                    "severity": "CRITICAL",
                    "issue": "Referenced file is world-writable",
                    "path": file_path,
                })

        except FileNotFoundError:
            continue
        except PermissionError:
            result["errors"].append(
                f"Permission denied while inspecting {file_path}"
            )
        except OSError as error:
            result["errors"].append(
                f"{file_path}: {error}"
            )

    return result


def scan_periodic_cron_directories(paths=None):
    """
    Inspect periodic cron directories and executable run-parts scripts.

    Only eligible regular executable files are inspected.
    No scripts are executed or modified.
    """
    if paths is None:
        paths = [
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/cron.yearly",
        ]

    result = {
        "directories_inspected": [],
        "scripts_inspected": [],
        "findings": [],
        "errors": [],
    }

    for directory in paths:
        directory_info = inspect_cron_file(directory)

        result["directories_inspected"].append(directory_info)

        result["findings"].extend(directory_info["issues"])

        if not directory_info["exists"]:
            result["errors"].extend(
                f"{directory}: {error}"
                for error in directory_info["errors"]
            )
            continue

        if not directory_info["is_directory"]:
            result["errors"].append(
                f"{directory}: Path is not a directory"
            )
            continue

        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    # run-parts normally ignores hidden files and names
                    # containing characters outside letters, digits,
                    # underscores and hyphens.
                    if not re.fullmatch(
                        r"[A-Za-z0-9_-]+",
                        entry.name
                    ):
                        continue

                    if not entry.is_file(follow_symlinks=False):
                        continue

                    file_stat = entry.stat(follow_symlinks=False)

                    if not file_stat.st_mode & (
                        stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                    ):
                        continue

                    script_info = inspect_cron_file(entry.path)

                    result["scripts_inspected"].append(script_info)
                    result["findings"].extend(script_info["issues"])
                    result["errors"].extend(
                        f"{entry.path}: {error}"
                        for error in script_info["errors"]
                    )

        except PermissionError:
            result["errors"].append(
                f"Permission denied while scanning {directory}"
            )
        except OSError as error:
            result["errors"].append(
                f"{directory}: {error}"
            )

    return result


if __name__ == "__main__":
    print("=" * 65)
    print("       LINUX CRON JOBS SECURITY SCANNER")
    print("=" * 65)

    # Phase 1: Cron configuration metadata inspection
    print("\n[1] CRON CONFIGURATION INSPECTION")

    for cron_path in DEFAULT_CRON_PATHS:
        result = inspect_cron_file(cron_path)

        print(f"\nPath: {result['path']}")
        print(f"Exists: {result['exists']}")

        if result["exists"]:
            print(f"Owner: {result['owner']}")
            print(f"Group: {result['group']}")
            print(f"Permissions: {result['permissions']}")

        for issue in result["issues"]:
            print(f"Finding: {issue['issue']}")
            print(f"Severity: {issue['severity']}")

        for error in result["errors"]:
            print(f"Error: {error}")

    # Phase 2: Periodic cron directory inspection
    print("\n[2] PERIODIC CRON SCRIPT INSPECTION")

    periodic_result = scan_periodic_cron_directories()

    for script in periodic_result["scripts_inspected"]:
        print(f"\nScript: {script['path']}")
        print(f"Owner: {script['owner']}")
        print(f"Group: {script['group']}")
        print(f"Permissions: {script['permissions']}")

    print("\nPeriodic Directory Findings:")

    for finding in periodic_result["findings"]:
        print(
            f"[{finding['severity']}] "
            f"{finding['issue']} | {finding['path']}"
        )

    for error in periodic_result["errors"]:
        print(f"Inspection error: {error}")

    print("\n" + "=" * 65)
    print("CRON SCANNER SUMMARY")
    print("=" * 65)

    print("Periodic directories inspected:",
          len(periodic_result["directories_inspected"]))

    print("Periodic scripts inspected:",
          len(periodic_result["scripts_inspected"]))

    print("Periodic security findings:",
          len(periodic_result["findings"]))

    print("Inspection errors:",
          len(periodic_result["errors"]))

    print("\nDetection only; no cron jobs or scripts were executed.")
    print("=" * 65)
