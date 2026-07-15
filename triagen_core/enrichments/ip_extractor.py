import re

_IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def extract_ip(text: str) -> list[str]:
    """
    Returns every IPv4 literal found in the given text (e.g. a command
    line), in order of appearance. Empty list if none are present.
    """
    if not text:
        return []
    return _IPV4_PATTERN.findall(text)
