def apply_filters(alert):
    """
    Returns alert if it passes all filters.
    Otherwise returns None.
    """

    if alert is None:
        return None

    severity = alert.get("severity", 0)

    if severity < 7:
        return None

    mitre = alert.get("mitre", [])

    if not mitre:
        return None

    return alert
