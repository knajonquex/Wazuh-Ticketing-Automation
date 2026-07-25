import json
from pathlib import Path

from config import RAW_ALERT_DIRECTORY


def save_raw_alert(raw_alert, incident_id):
    """
    Persist the original, unmodified raw Wazuh alert (the exact JSON line
    read from alerts.json, before parsing/flattening/enrichment) to disk,
    pretty-printed for readability, keyed by incident ID.

    Returns the path to the saved file.
    """

    directory = Path(RAW_ALERT_DIRECTORY)
    directory.mkdir(parents=True, exist_ok=True)

    file_path = directory / f"{incident_id}.json"

    try:
        parsed = json.loads(raw_alert)
        contents = json.dumps(parsed, indent=2, ensure_ascii=False)

    except (TypeError, ValueError):
        # Not valid JSON for some reason -- write out whatever we got
        # rather than losing the raw evidence.
        contents = str(raw_alert)

    with file_path.open("w", encoding="utf-8") as f:
        f.write(contents)

    return str(file_path)
