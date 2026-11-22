import os
import re
import stat
import pwd
import grp
import subprocess
import shutil


SYSTEMCTL = "/usr/bin/systemctl"

SERVICE_PROPERTIES = [
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "FragmentPath",
    "DropInPaths",
    "User",
    "Group",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "EnvironmentFiles",
    "UnitFileState",
]


def get_owner_name(uid):
    """Return username for a UID."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def get_group_name(gid):
    """Return group name for a GID."""
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def run_systemctl(arguments, timeout=15):
    """Run a read-only systemctl query."""
    try:
        result = subprocess.run(
            [SYSTEMCTL] + arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            return None, result.stderr.strip() or "systemctl query failed"

        return result.stdout, None

    except FileNotFoundError:
        return None, "systemctl executable not found"
    except subprocess.TimeoutExpired:
        return None, "systemctl query timed out"
    except OSError as error:
        return None, str(error)


def list_service_units():
    """Discover system service units."""
    output, error = run_systemctl([
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--no-pager",
    ])

    if error:
        return {"services": [], "error": error}

    services = []

    for line in output.splitlines():
        parts = line.split()

        if parts and parts[0].endswith(".service"):
            services.append(parts[0])

    return {"services": sorted(set(services)), "error": None}


def get_service_properties(service_name):
    """Collect selected properties for one service."""
    output, error = run_systemctl([
        "show",
        service_name,
        "--no-pager",
        *[f"--property={item}" for item in SERVICE_PROPERTIES],
    ])

    if error:
        return None, error

    properties = {}

    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value

    return properties, None


def inspect_path(path):
    """Inspect ownership and permissions without changing the path."""
    if not path:
        return {
            "path": path,
            "exists": False,
            "error": "Empty path",
        }

    try:
        info = os.stat(path)

        mode = stat.S_IMODE(info.st_mode)
        is_regular_file = stat.S_ISREG(info.st_mode)

        return {
            "path": path,
            "exists": True,
            "is_regular_file": is_regular_file,
            "owner": get_owner_name(info.st_uid),
            "group": get_group_name(info.st_gid),
            "permissions": oct(mode),
            "group_writable": bool(mode & stat.S_IWGRP),
            "world_writable": bool(mode & stat.S_IWOTH),
            "is_symlink": os.path.islink(path),
            "error": None,
        }

    except FileNotFoundError:
        return {
            "path": path,
            "exists": False,
            "error": "Path does not exist",
        }

    except PermissionError:
        return {
            "path": path,
            "exists": False,
            "error": "Permission denied",
        }

    except OSError as error:
        return {
            "path": path,
            "exists": False,
            "error": str(error),
        }


def extract_command_paths(properties):
    """Extract and resolve executable paths from systemd command properties."""
    paths = {}

    command_properties = [
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
    ]

    for property_name in command_properties:
        value = properties.get(property_name, "")

        matches = re.findall(r"path=([^ ;}]+)", value)
        resolved_paths = []

        for command in matches:
            if os.path.isabs(command):
                resolved = command
            else:
                # Resolve command names such as systemctl using PATH.
                resolved = shutil.which(command)

            # Ignore unresolved command names instead of reporting
            # misleading missing-executable findings.
            if resolved:
                resolved_paths.append(resolved)

        if resolved_paths:
            paths[property_name] = list(dict.fromkeys(resolved_paths))

    return paths


def extract_environment_paths(value):
    """Extract absolute environment-file paths from systemd properties."""
    if not value:
        return []

    # Supports formats such as:
    # /etc/default/cron (ignore_errors=yes)
    # { /etc/default/cron (ignore_errors=yes) }

    matches = re.findall(r"(?<!\S)-?(/[^\s(){}]+)", value)

    return list(dict.fromkeys(path.strip().lstrip("-") for path in matches))


def inspect_service(service_name):
    """Inspect one systemd service."""
    properties, error = get_service_properties(service_name)

    if error:
        return {
            "service": service_name,
            "error": error,
        }

    user = properties.get("User", "").strip()

    # An empty User property means root for a system service.
    runs_as_root = user in ("", "root", "0")

    fragment_path = properties.get("FragmentPath", "").strip()

    drop_in_paths = properties.get("DropInPaths", "").split()

    unit_paths = []

    if fragment_path:
        unit_paths.append(fragment_path)

    unit_paths.extend(drop_in_paths)

    unit_inspections = [
        inspect_path(path) for path in dict.fromkeys(unit_paths)
    ]

    command_paths = extract_command_paths(properties)

    executable_inspections = []

    for property_name, paths in command_paths.items():
        for path in paths:
            result = inspect_path(path)
            result["source_property"] = property_name
            executable_inspections.append(result)

    environment_paths = extract_environment_paths(
        properties.get("EnvironmentFiles", "")
    )

    environment_inspections = [
        inspect_path(path) for path in environment_paths
    ]

    findings = []
    observations = []

    if runs_as_root:
        observations.append({
            "severity": "INFO",
            "issue": "Service runs with root privileges",
            "path": service_name,
        })

    for item in unit_inspections:
        if item.get("group_writable"):
            findings.append({
                "severity": "HIGH",
                "issue": "Group-writable systemd unit or drop-in file",
                "path": item["path"],
            })

        if item.get("world_writable"):
            findings.append({
                "severity": "CRITICAL",
                "issue": "World-writable systemd unit or drop-in file",
                "path": item["path"],
            })

    for item in executable_inspections:
        if not item.get("exists"):
            findings.append({
                "severity": "LOW",
                "issue": "Referenced service executable is missing or inaccessible",
                "path": item["path"],
            })
        elif item.get("group_writable"):
            findings.append({
                "severity": "HIGH",
                "issue": "Group-writable service executable",
                "path": item["path"],
            })
        elif item.get("world_writable"):
            findings.append({
                "severity": "CRITICAL",
                "issue": "World-writable service executable",
                "path": item["path"],
            })

    for item in environment_inspections:
        if not item.get("exists"):
            findings.append({
                "severity": "LOW",
                "issue": "Referenced environment file is missing or inaccessible",
                "path": item["path"],
            })
        elif item.get("group_writable"):
            findings.append({
                "severity": "HIGH",
                "issue": "Group-writable service environment file",
                "path": item["path"],
            })
        elif item.get("world_writable"):
            findings.append({
                "severity": "CRITICAL",
                "issue": "World-writable service environment file",
                "path": item["path"],
            })

    return {
        "service": service_name,
        "active_state": properties.get("ActiveState", "unknown"),
        "sub_state": properties.get("SubState", "unknown"),
        "unit_file_state": properties.get("UnitFileState", "unknown"),
        "user": user or "root (default)",
        "group": properties.get("Group", "") or "root (default)",
        "runs_as_root": runs_as_root,
        "unit_files": unit_inspections,
        "executables": executable_inspections,
        "environment_files": environment_inspections,
        "findings": findings,
        "observations": observations,
        "error": None,
    }


def scan_systemd_services():
    """Discover and inspect systemd services."""
    discovery = list_service_units()

    if discovery["error"]:
        return {
            "services_scanned": 0,
            "services": [],
            "findings": [],
            "errors": [discovery["error"]],
        }

    results = []
    errors = []

    for service_name in discovery["services"]:
        result = inspect_service(service_name)
        results.append(result)

        if result.get("error"):
            errors.append(
                f"{service_name}: {result['error']}"
            )

    all_findings = []

    for result in results:
        all_findings.extend(result.get("findings", []))

    return {
        "services_scanned": len(results),
        "services": results,
        "findings": all_findings,
        "errors": errors,
    }


def display_results(results):
    """Display security findings separately from informational observations."""
    print("\n========== SYSTEMD SECURITY SCAN ==========")

    print(f"Services scanned : {results['services_scanned']}")
    print(f"Security findings: {len(results['findings'])}")

    observation_count = sum(
        len(service.get("observations", []))
        for service in results["services"]
    )

    print(f"Observations     : {observation_count}")
    print(f"Scan errors      : {len(results['errors'])}")

    for service in results["services"]:
        if service.get("error"):
            continue

        print("\n-------------------------------------------")
        print(f"Service       : {service['service']}")
        print(f"Active state  : {service['active_state']}")
        print(f"Execution user: {service['user']}")

        for observation in service.get("observations", []):
            print(f"\n[{observation['severity']}] {observation['issue']}")
            print(f"Path: {observation['path']}")

        for finding in service["findings"]:
            print(f"\n[{finding['severity']}] {finding['issue']}")
            print(f"Path: {finding['path']}")

    if results["errors"]:
        print("\nScan errors:")

        for error in results["errors"]:
            print(f"- {error}")


if __name__ == "__main__":
    scan_results = scan_systemd_services()
    display_results(scan_results)
