_SERVER_MARKERS = ["srv", "server", "dc0", "dc1", "sql", "db0", "prod", "web0", "app0"]


def is_server_name(hostname: str) -> bool:
    """
    Heuristic check for server/infrastructure naming conventions, as
    opposed to end-user workstation names.
    """
    if not hostname:
        return False
    lowered = hostname.lower()
    return any(marker in lowered for marker in _SERVER_MARKERS)
