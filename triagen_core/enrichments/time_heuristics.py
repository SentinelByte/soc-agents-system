from datetime import datetime, timezone


def is_off_hours(timestamp: str, start_hour: int = 7, end_hour: int = 20) -> bool:
    """
    True if the alert's timestamp falls outside a normal business-hours
    window (UTC). A coarse heuristic: it ignores timezone/locale nuance and
    treats weekends the same as weekdays.
    """
    if not timestamp:
        return False
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return False
    return not (start_hour <= parsed.hour < end_hour)
