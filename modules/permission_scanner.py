import os
import stat
import pwd
import grp


DEFAULT_SCAN_PATHS = [
    "/etc",
    "/home",
    "/opt",
    "/usr/local"
]

SENSITIVE_FILE_POLICIES = {
    "/etc/passwd": {"group": "root", "world_read": True},
    "/etc/group": {"group": "root", "world_read": True},
    "/etc/shadow": {"group": "shadow", "world_read": False},
    "/etc/gshadow": {"group": "shadow", "world_read": False},
    "/etc/sudoers": {"group": "root", "world_read": False}
}

PRIVATE_KEY_NAMES = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa"
}


def get_owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def get_group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def check_file_permissions(file_path, file_stat):
    findings = []

    mode = file_stat.st_mode
    owner = get_owner_name(file_stat.st_uid)
    group = get_group_name(file_stat.st_gid)

    is_directory = stat.S_ISDIR(mode)
    world_writable = bool(mode & stat.S_IWOTH)
    group_writable = bool(mode & stat.S_IWGRP)
    has_sticky_bit = bool(mode & stat.S_ISVTX)

    # 1. World-writable file and directory detection
    if world_writable:

        if is_directory and has_sticky_bit:
            severity = "LOW"
            reason = "World-writable directory protected by sticky bit"

        elif is_directory:
            severity = "HIGH"
            reason = "World-writable directory without sticky bit"

        else:
            severity = "HIGH"
            reason = "World-writable file"

        findings.append({
            "path": file_path,
            "issue": "World-writable permission",
            "severity": severity,
            "reason": reason
        })

    # 2. Sensitive system-file checks
    normalized_path = os.path.normpath(file_path)

    if normalized_path in SENSITIVE_FILE_POLICIES:

        policy = SENSITIVE_FILE_POLICIES[normalized_path]
        expected_group = policy["group"]

        if owner != "root":
            findings.append({
                "path": file_path,
                "issue": "Unexpected sensitive-file ownership",
                "severity": "CRITICAL",
                "reason": f"Expected root ownership, found {owner}"
            })

        if group != expected_group:
            findings.append({
                "path": file_path,
                "issue": "Unexpected sensitive-file group",
                "severity": "HIGH",
                "reason": f"Expected group {expected_group}, found {group}"
            })

        if group_writable or world_writable:
            findings.append({
                "path": file_path,
                "issue": "Unsafe sensitive-file permissions",
                "severity": "CRITICAL",
                "reason": "Sensitive file is group-writable or world-writable"
            })

        if mode & stat.S_IROTH and not policy["world_read"]:
            findings.append({
                "path": file_path,
                "issue": "Sensitive-file world-readable",
                "severity": "HIGH",
                "reason": "Sensitive file is readable by everyone"
            })

    # 3. Private-key permission checks
    if os.path.basename(file_path) in PRIVATE_KEY_NAMES:

        unsafe_access = mode & (
            stat.S_IRGRP |
            stat.S_IROTH |
            stat.S_IWGRP |
            stat.S_IWOTH
        )

        if unsafe_access:
            findings.append({
                "path": file_path,
                "issue": "Private key permissions",
                "severity": "HIGH",
                "reason": "Private key is accessible to group or others"
            })

    return findings


def scan_permissions(scan_paths=None):

    if scan_paths is None:
        scan_paths = DEFAULT_SCAN_PATHS

    findings = []
    errors = []

    scanned_files = 0
    scanned_directories = 0

    visited_directories = set()

    for scan_path in scan_paths:

        if not os.path.exists(scan_path):
            continue

        if os.path.islink(scan_path):
            continue

        for root, directories, files in os.walk(
            scan_path,
            followlinks=False,
            onerror=lambda error: errors.append(str(error))
        ):

            real_root = os.path.realpath(root)

            if real_root in visited_directories:
                directories[:] = []
                continue

            visited_directories.add(real_root)

            directories[:] = [
                directory for directory in directories
                if not os.path.islink(os.path.join(root, directory))
            ]

            for directory in directories:

                directory_path = os.path.join(root, directory)

                try:
                    directory_stat = os.stat(
                        directory_path,
                        follow_symlinks=False
                    )

                    scanned_directories += 1

                    findings.extend(
                        check_file_permissions(
                            directory_path,
                            directory_stat
                        )
                    )

                except OSError as error:
                    errors.append(f"{directory_path}: {error}")

            for filename in files:

                file_path = os.path.join(root, filename)

                try:
                    file_stat = os.stat(
                        file_path,
                        follow_symlinks=False
                    )

                    if not stat.S_ISREG(file_stat.st_mode):
                        continue

                    scanned_files += 1

                    findings.extend(
                        check_file_permissions(file_path, file_stat)
                    )

                except OSError as error:
                    errors.append(f"{file_path}: {error}")

    return {
        "scanned_files": scanned_files,
        "scanned_directories": scanned_directories,
        "total_findings": len(findings),
        "findings": findings,
        "errors": errors
    }


def display_results(results):

    print("\n" + "=" * 65)
    print("             LINUX PERMISSION SECURITY SCAN")
    print("=" * 65)

    print(f"Files scanned       : {results['scanned_files']}")
    print(f"Directories scanned : {results['scanned_directories']}")
    print(f"Total findings      : {results['total_findings']}")
    print(f"Scan errors         : {len(results['errors'])}")

    if not results["findings"]:
        print("\nNo permission issues detected.")

    for index, finding in enumerate(results["findings"], start=1):

        print(f"\nFinding #{index}")
        print("-" * 50)
        print(f"Path     : {finding['path']}")
        print(f"Issue    : {finding['issue']}")
        print(f"Severity : {finding['severity']}")
        print(f"Reason   : {finding['reason']}")

    print("\n" + "=" * 65)
    print("NOTE: Findings require contextual security review.")
    print("=" * 65)


if __name__ == "__main__":

    results = scan_permissions()
    display_results(results)
