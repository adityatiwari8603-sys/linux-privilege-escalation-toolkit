import os
import subprocess

import modules.capabilities_scanner as scanner


def test_parse_multiple_capabilities():

    result = scanner.parse_capability_line(
        "/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip"
    )

    assert result["path"] == "/usr/bin/dumpcap"

    assert result["capabilities"] == [
        "cap_net_admin",
        "cap_net_raw",
    ]

    assert result["flags"] == "eip"


def test_parse_single_capability():

    result = scanner.parse_capability_line(
        "/usr/bin/fping cap_net_raw=ep"
    )

    assert result["capabilities"] == ["cap_net_raw"]
    assert result["flags"] == "ep"


def test_parse_path_with_spaces():

    result = scanner.parse_capability_line(
        "/tmp/test application cap_net_raw=ep"
    )

    assert result["path"] == "/tmp/test application"


def test_parse_empty_line():

    assert scanner.parse_capability_line("") is None


def test_parse_invalid_line():

    assert scanner.parse_capability_line(
        "invalid capability output"
    ) is None


def test_inspect_file(tmp_path):

    test_file = tmp_path / "test_file"

    test_file.write_text("test")

    result = scanner.inspect_file(str(test_file))

    assert result["exists"] is True
    assert result["is_regular_file"] is True
    assert result["owner"]
    assert result["group"]


def test_world_writable_file_detection():

    parsed = {
        "path": "/tmp/test",
        "capabilities": ["cap_net_raw"],
        "flags": "ep",
    }

    file_info = {
        "world_writable": True,
        "group_writable": False,
    }

    findings = scanner.analyze_capabilities(
        parsed,
        file_info,
    )

    assert any(
        finding["severity"] == "CRITICAL"
        for finding in findings
    )


def test_high_risk_capability_detection():

    parsed = {
        "path": "/tmp/test",
        "capabilities": ["cap_sys_admin"],
        "flags": "ep",
    }

    file_info = {
        "world_writable": False,
        "group_writable": False,
    }

    findings = scanner.analyze_capabilities(
        parsed,
        file_info,
    )

    assert any(
        finding["severity"] == "HIGH"
        for finding in findings
    )


def test_group_writable_file_detection():

    parsed = {
        "path": "/tmp/test",
        "capabilities": ["cap_net_raw"],
        "flags": "ep",
    }

    file_info = {
        "world_writable": False,
        "group_writable": True,
    }

    findings = scanner.analyze_capabilities(
        parsed,
        file_info,
    )

    assert any(
        finding["severity"] == "HIGH"
        for finding in findings
    )


def test_scan_capabilities_success(monkeypatch, tmp_path):

    test_file = tmp_path / "test_binary"
    test_file.write_text("test")

    monkeypatch.setattr(
        scanner,
        "GETCAP",
        "/usr/sbin/getcap",
    )

    def mock_run(*args, **kwargs):

        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=f"{test_file} cap_net_raw=ep\n",
            stderr="",
        )

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        mock_run,
    )

    result = scanner.scan_capabilities(
        scan_paths=[str(tmp_path)]
    )

    assert result["capability_files_found"] == 1
    assert len(result["observations"]) == 1
    assert result["errors"] == []


def test_missing_getcap(monkeypatch):

    monkeypatch.setattr(
        scanner,
        "GETCAP",
        None,
    )

    result = scanner.scan_capabilities()

    assert len(result["errors"]) == 1
    assert result["capability_files_found"] == 0


def test_scan_timeout(monkeypatch, tmp_path):

    monkeypatch.setattr(
        scanner,
        "GETCAP",
        "/usr/sbin/getcap",
    )

    def mock_run(*args, **kwargs):

        raise subprocess.TimeoutExpired(
            cmd="getcap",
            timeout=60,
        )

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        mock_run,
    )

    result = scanner.scan_capabilities(
        scan_paths=[str(tmp_path)]
    )

    assert any(
        "timed out" in error.lower()
        for error in result["errors"]
    )

