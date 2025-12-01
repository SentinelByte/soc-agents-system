'''
~~ Alert Processor
Responsible for:
1. Validating minimal alert structure
2. Normalizing keys & types
3. Classifying the alert into a category:
   - process
   - command
   - network
   - file
   - auth
   - unknown
'''

from typing import Dict, Any

## Minimal required fields
REQUIRED_FIELDS = [
    "alert_type",
    "timestamp",
    "user",
    "hostname",
]


## Validation
def validate_alert(alert: Dict[str, Any]):
    missing = [key for key in REQUIRED_FIELDS if key not in alert]

    if missing:
        raise ValueError(f"Alert missing required fields: {missing}")

    return True

## Normalization
def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Ensures all expected keys exist and are well-formed.
    Fills optional structures with empty defaults if missing.
    '''

    normalized = alert.copy()

    ## optional but common fields
    normalized.setdefault("details", {})
    normalized.setdefault("raw_log", "")

    return normalized


## Routing / Classification
def classify_alert(alert: Dict[str, Any]) -> str:
    '''
    Decide what type of investigation this alert should follow.
    '''

    alert_type = alert.get("alert_type", "").lower()

    ## basic categories; can expand later
    if any(x in alert_type for x in ["process", "cmd", "command"]):
        return "process"

    if any(x in alert_type for x in ["network", "conn", "ip", "traffic"]):
        return "network"

    if any(x in alert_type for x in ["file", "malware", "hash"]):
        return "file"

    if any(x in alert_type for x in ["auth", "login", "credential"]):
        return "auth"

    return "unknown"

## Main function used by triage_pipeline()
def process_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Full alert processing pipeline:
    - validate
    - normalize
    - classify
    '''

    validate_alert(alert)
    normalized = normalize_alert(alert)
    category = classify_alert(normalized)

    normalized["category"] = category

    return normalized
