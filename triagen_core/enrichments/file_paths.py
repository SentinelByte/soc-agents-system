_SENSITIVE_PATH_MARKERS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/.ssh/id_rsa",
    "~/.ssh/",
    "/.aws/credentials",
    "system32\\config\\sam",
    "ntds.dit",
    "\\ntds\\",
    "/var/log/auth.log",
]


def contains_sensitive_path(cmd: str) -> bool:
    """
    Flags commands that reference paths commonly targeted for credential
    theft, persistence, or log tampering.
    """
    if not cmd:
        return False
    lowered = cmd.lower()
    return any(marker in lowered for marker in _SENSITIVE_PATH_MARKERS)
