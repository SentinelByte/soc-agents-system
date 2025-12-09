from typing import Dict, Any
import re

## Enrichments modules (from dir: /enrichments)
from .enrichments.file_paths import contains_sensitive_path
from .enrichments.network_tools import executes_network_tools
from .enrichments.time_heuristics import is_off_hours
from .enrichments.command_flags import scan_command_flags
from .enrichments.ip_extractor import extract_ip
from .enrichments.user_privilege import is_privileged_user
from .enrichments.hostname_check import is_server_name

def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Enriches a normalized alert with metadata and heuristic flags.
    Lightweight enrichment step for local processing.
    '''
    enriched = alert.copy()
    details = enriched.get("details", {})

    ## Command-based enrichment
    if "command" in details:
        cmd = details["command"]
        enriched["command_length"] = len(cmd)
        enriched["contains_suspicious_flags"] = scan_command_flags(cmd)
        enriched["contains_ip_address"] = extract_ip(cmd)
        enriched["references_sensitive_path"] = contains_sensitive_path(cmd)
        enriched["executes_network_tool"] = executes_network_tools(cmd)

    ## User and hostname heuristics
    enriched["user_is_privileged"] = is_privileged_user(enriched.get("user"))
    enriched["hostname_is_server"] = is_server_name(enriched.get("hostname"))

    ## Time-based enrichment
    enriched["occurred_off_hours"] = is_off_hours(enriched.get("timestamp", ""))

    return enriched

