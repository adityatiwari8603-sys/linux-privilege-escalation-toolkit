"""
System Information Collector

Collects Linux system and user information for security auditing.
This module is read-only.
"""

import os
import platform
import pwd
import grp
from datetime import datetime, timezone


def collect_system_info():
    """Collect system, operating system, and user information."""

    current_uid = os.getuid()
    current_gid = os.getgid()

    user_info = pwd.getpwuid(current_uid)
    group_info = grp.getgrgid(current_gid)

    group_names = []

    for group_id in os.getgroups():
        try:
            group_names.append(grp.getgrgid(group_id).gr_name)
        except KeyError:
            group_names.append(str(group_id))

    distribution = {}

    try:
        with open("/etc/os-release", "r", encoding="utf-8") as file:
            for line in file:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    distribution[key] = value.strip('"')
    except OSError:
        distribution = {"NAME": "Unknown"}

    system_info = {
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "distribution": distribution.get("PRETTY_NAME", "Unknown"),
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "username": user_info.pw_name,
        "uid": current_uid,
        "gid": current_gid,
        "primary_group": group_info.gr_name,
        "groups": group_names,
        "home_directory": user_info.pw_dir,
        "collection_time": datetime.now(timezone.utc).isoformat()
    }

    return system_info


def display_system_info(system_info):
    """Display collected information in a readable format."""

    print("\n" + "=" * 60)
    print("       LINUX SYSTEM SECURITY AUDIT")
    print("=" * 60)

    for key, value in system_info.items():
        label = key.replace("_", " ").title()
        print(f"{label:<25}: {value}")

    print("=" * 60)


if __name__ == "__main__":
    information = collect_system_info()
    display_system_info(information)
