import re
from typing import Dict, Any

def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Enriches a normalized alert with basic metadata and heuristic flags.
    This is a lightweight enrichment step for local processing.
    '''

    enriched = alert.copy()
    details = enriched.get("details", {})

    ## Enrich with command indicators
    if "command" in details:
        cmd = details["command"]

        enriched["command_length"] = len(cmd)
        enriched["contains_suspicious_flags"] = _scan_command_flags(cmd)
        enriched["contains_ip_address"] = _extract_ip(cmd)

    ## Enrich with user-related heuristics
    enriched["user_is_privileged"] = _is_privileged_user(enriched.get("user"))

    ## Enrich with hostname heuristics
    enriched["hostname_is_server"] = _is_server_name(enriched.get("hostname"))

    return enriched

## Internal helpers
def _scan_command_flags(cmd: str) -> bool:
    '''Detects potentially risky flags in a command string.'''
    suspicious_patterns = ["-e", "--exec", "--interactive", "-i", "-f"]
    return any(flag in cmd for flag in suspicious_patterns)

def _extract_ip(text: str) -> str:
    '''Extracts first IPv4 address from text, returns empty string if none.'''
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, text)
    return match.group(0) if match else ""

def _is_privileged_user(user: str) -> bool:
    privileged = ["root", "administrator", "system", "admin"]
    if not user:
        return False
    return user.lower() in privileged

def _is_server_name(hostname: str) -> bool:
    if not hostname:
        return False
    return any(x in hostname.lower() for x in ["srv", "server", "prd", "prod"])
