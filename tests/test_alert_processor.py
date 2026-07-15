import pytest

from triagen_core.alert_processor import classify_alert, process_alert, validate_alert

BASE_ALERT = {
    "alert_type": "process_start",
    "timestamp": "2026-07-14T02:13:00Z",
    "user": "alice",
    "hostname": "host1",
}


def test_validate_alert_raises_on_missing_fields():
    with pytest.raises(ValueError):
        validate_alert({"alert_type": "process_start"})


def test_validate_alert_passes_with_required_fields():
    assert validate_alert(BASE_ALERT) is True


@pytest.mark.parametrize(
    "alert_type,expected_category",
    [
        ("process_start", "process"),
        ("suspicious_command", "process"),
        ("network_connection", "network"),
        ("file_write_malware", "file"),
        ("auth_login", "auth"),
        ("something_else", "unknown"),
    ],
)
def test_classify_alert(alert_type, expected_category):
    alert = {**BASE_ALERT, "alert_type": alert_type}
    assert classify_alert(alert) == expected_category


def test_process_alert_fills_defaults_and_sets_category():
    result = process_alert(BASE_ALERT)
    assert result["category"] == "process"
    assert result["details"] == {}
    assert result["raw_log"] == ""
