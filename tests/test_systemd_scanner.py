import os
import pytest

from modules import systemd_scanner as scanner


def test_extract_environment_paths():
    value = "/etc/default/pcscd (ignore_errors=yes)"

    assert scanner.extract_environment_paths(value) == [
        "/etc/default/pcscd"
    ]


def test_extract_environment_paths_multiple():
    value = (
        "/etc/default/cron (ignore_errors=yes) "
        "/etc/default/example.conf"
    )

    assert scanner.extract_environment_paths(value) == [
        "/etc/default/cron",
        "/etc/default/example.conf",
    ]


def test_extract_environment_paths_empty():
    assert scanner.extract_environment_paths("") == []


def test_extract_command_paths_absolute():
    properties = {
        "ExecStart": "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 }"
    }

    result = scanner.extract_command_paths(properties)

    assert result["ExecStart"] == ["/usr/bin/python3"]


def test_extract_command_paths_resolves_command(monkeypatch):
    monkeypatch.setattr(
        scanner.shutil,
        "which",
        lambda command: "/usr/bin/systemctl"
        if command == "systemctl"
        else None,
    )

    properties = {
        "ExecStart": "{ path=systemctl ; argv[]=systemctl }"
    }

    result = scanner.extract_command_paths(properties)

    assert result["ExecStart"] == ["/usr/bin/systemctl"]


def test_extract_command_paths_ignores_unresolved(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda command: None)

    properties = {
        "ExecStart": "{ path=unknown-command ; argv[]=unknown-command }"
    }

    assert scanner.extract_command_paths(properties) == {}


def test_extract_command_paths_empty():
    assert scanner.extract_command_paths({}) == {}


def test_inspect_path_existing_file(tmp_path):
    test_file = tmp_path / "test.service"
    test_file.write_text("[Service]\n")

    result = scanner.inspect_path(str(test_file))

    assert result["exists"] is True
    assert result["is_regular_file"] is True
    assert result["error"] is None
    assert result["path"] == str(test_file)


def test_inspect_path_missing_file(tmp_path):
    missing_file = tmp_path / "missing.service"

    result = scanner.inspect_path(str(missing_file))

    assert result["exists"] is False
    assert result["error"] == "Path does not exist"


def test_inspect_path_empty():
    result = scanner.inspect_path("")

    assert result["exists"] is False
    assert result["error"] == "Empty path"


def test_root_service_observation(monkeypatch):
    properties = {
        "User": "",
        "Group": "",
        "FragmentPath": "",
        "DropInPaths": "",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
    }

    monkeypatch.setattr(
        scanner,
        "get_service_properties",
        lambda name: (properties, None),
    )

    result = scanner.inspect_service("example.service")

    assert result["runs_as_root"] is True
    assert len(result["observations"]) == 1
    assert result["observations"][0]["severity"] == "INFO"


def test_non_root_service(monkeypatch):
    properties = {
        "User": "nobody",
        "Group": "nogroup",
        "FragmentPath": "",
        "DropInPaths": "",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
    }

    monkeypatch.setattr(
        scanner,
        "get_service_properties",
        lambda name: (properties, None),
    )

    result = scanner.inspect_service("example.service")

    assert result["runs_as_root"] is False
    assert result["observations"] == []


def test_missing_service_executable(monkeypatch):
    properties = {
        "User": "",
        "Group": "",
        "FragmentPath": "",
        "DropInPaths": "",
        "ExecStart": "{ path=/missing/example-program ; argv[]=example-program }",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "enabled",
    }

    monkeypatch.setattr(
        scanner,
        "get_service_properties",
        lambda name: (properties, None),
    )

    result = scanner.inspect_service("example.service")

    assert any(
        finding["issue"]
        == "Referenced service executable is missing or inaccessible"
        for finding in result["findings"]
    )


def test_service_property_error(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "get_service_properties",
        lambda name: (None, "systemctl query failed"),
    )

    result = scanner.inspect_service("example.service")

    assert result["error"] == "systemctl query failed"


def test_scan_systemd_services_aggregates(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "list_service_units",
        lambda: {
            "services": ["one.service", "two.service"],
            "error": None,
        },
    )

    monkeypatch.setattr(
        scanner,
        "inspect_service",
        lambda name: {
            "service": name,
            "findings": [
                {"severity": "LOW", "issue": "Test finding", "path": name}
            ],
            "error": None,
        },
    )

    result = scanner.scan_systemd_services()

    assert result["services_scanned"] == 2
    assert len(result["services"]) == 2
    assert len(result["findings"]) == 2
    assert result["errors"] == []


def test_scan_systemd_services_discovery_error(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "list_service_units",
        lambda: {
            "services": [],
            "error": "systemd unavailable",
        },
    )

    result = scanner.scan_systemd_services()

    assert result["services_scanned"] == 0
    assert result["findings"] == []
    assert result["errors"] == ["systemd unavailable"]
