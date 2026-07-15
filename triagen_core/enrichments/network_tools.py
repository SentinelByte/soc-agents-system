_NETWORK_TOOL_MARKERS = [
    "nc ",
    "ncat",
    "netcat",
    "socat",
    "curl ",
    "wget ",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "invoke-webrequest",
    "iwr ",
    "python -m http.server",
    "powershell -nop",
    "ssh ",
    "scp ",
    "telnet ",
    "/dev/tcp/",
]


def executes_network_tools(cmd: str) -> bool:
    """
    Flags commands that invoke tools commonly used for reverse shells,
    payload staging, or command-and-control communication.
    """
    if not cmd:
        return False
    lowered = cmd.lower()
    return any(marker in lowered for marker in _NETWORK_TOOL_MARKERS)
