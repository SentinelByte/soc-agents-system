_PRIVILEGED_MARKERS = ["root", "admin", "administrator", "system", "svc_", "service_"]


def is_privileged_user(user: str) -> bool:
    """
    Heuristic check for privileged/service account usage based on naming
    convention. Not a substitute for querying actual IAM/AD group
    membership -- this is a cheap early signal only.
    """
    if not user:
        return False
    lowered = user.lower()
    return any(lowered == marker or lowered.startswith(marker) for marker in _PRIVILEGED_MARKERS)
