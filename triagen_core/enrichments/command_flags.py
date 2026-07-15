import platform


def scan_command_flags(cmd: str, os_type: str = None) -> bool:
    '''
    Detect suspicious command flags based on OS.
    os_type should be: 'windows', 'linux', or 'macos'
    If os_type is not provided, auto-detect the host OS.
    '''

    # --- Auto-detect OS if not passed ---
    if os_type is None:
        system = platform.system().lower()
        if "windows" in system:
            os_type = "windows"
        elif "darwin" in system:
            os_type = "macos"
        else:
            os_type = "linux"

    windows_flags = ["/c", "/r", "/f", "/s", "/u", "/p", "-enc", "-noni", "-nop", "-w hidden"]

    linux_flags = [
        "-e", "-i", "-f", "--exec", "--interactive", "--force",
        "--bypass-security", "--no-sandbox", "-shell", "--shell", "--command",
    ]

    macos_flags = ["-e", "-i", "--exec", "--interactive", "--no-quarantine", "-stdin", "--force"]

    if os_type == "windows":
        suspicious_list = windows_flags
    elif os_type == "linux":
        suspicious_list = linux_flags
    elif os_type == "macos":
        suspicious_list = macos_flags
    else:
        suspicious_list = []  # Unknown OS → no flags checked

    return any(flag in cmd.lower() for flag in suspicious_list)
