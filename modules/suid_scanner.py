import os
import stat
import pwd
import grp


DEFAULT_SCAN_PATHS = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/opt"
]


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


def scan_suid_sgid(scan_paths=None):
    """
    Detect SUID and SGID files.

    This function only reads file metadata.
    It never executes discovered binaries.
    """

    if scan_paths is None:
        scan_paths = DEFAULT_SCAN_PATHS

    findings = []
    scanned_files = 0
    errors = []

    visited_directories = set()

    for scan_path in scan_paths:

        if not os.path.exists(scan_path):
            continue

        for root, directories, files in os.walk(
            scan_path,
            followlinks=False,
            onerror=lambda error: errors.append(str(error))
        ):

            try:
                real_root = os.path.realpath(root)

                if real_root in visited_directories:
                    directories[:] = []
                    continue

                visited_directories.add(real_root)

            except OSError as error:
                errors.append(str(error))
                continue

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

                    is_suid = bool(file_stat.st_mode & stat.S_ISUID)
                    is_sgid = bool(file_stat.st_mode & stat.S_ISGID)

                    if not is_suid and not is_sgid:
                        continue

                    findings.append({
                        "path": file_path,
                        "owner": get_owner_name(file_stat.st_uid),
                        "group": get_group_name(file_stat.st_gid),
                        "permissions": oct(
                            stat.S_IMODE(file_stat.st_mode)
                        ),
                        "suid": is_suid,
                        "sgid": is_sgid,
                        "size": file_stat.st_size
                    })

                except (PermissionError, FileNotFoundError, OSError) as error:
                    errors.append(f"{file_path}: {error}")

    return {
        "scanned_files": scanned_files,
        "total_findings": len(findings),
        "findings": findings,
        "errors": errors
    }


def display_findings(results):

    print("\n" + "=" * 65)
    print("             SUID / SGID SECURITY SCAN")
    print("=" * 65)

    print(f"Files scanned       : {results['scanned_files']}")
    print(f"Potential findings  : {results['total_findings']}")
    print(f"Scan errors         : {len(results['errors'])}")

    if not results["findings"]:
        print("\nNo SUID/SGID files found in the selected paths.")

    for index, finding in enumerate(results["findings"], start=1):

        print(f"\nFinding #{index}")
        print("-" * 50)
        print(f"Path        : {finding['path']}")
        print(f"Owner       : {finding['owner']}")
        print(f"Group       : {finding['group']}")
        print(f"Permissions : {finding['permissions']}")
        print(f"SUID        : {finding['suid']}")
        print(f"SGID        : {finding['sgid']}")

    print("\n" + "=" * 65)
    print("NOTE: Detection does not prove exploitability.")
    print("=" * 65)


if __name__ == "__main__":
    results = scan_suid_sgid()
    display_findings(results)
