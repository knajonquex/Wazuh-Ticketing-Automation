import json


def parse_hashes(hash_string):
    """
    Convert:
    SHA1=...,MD5=...,SHA256=...,IMPHASH=...

    into

    {
        "sha1": "...",
        "md5": "...",
        "sha256": "...",
        "imphash": "..."
    }
    """

    hashes = {
        "md5": None,
        "sha1": None,
        "sha256": None,
        "imphash": None
    }

    if not hash_string:
        return hashes

    for item in hash_string.split(","):

        if "=" not in item:
            continue

        key, value = item.split("=", 1)

        key = key.strip().lower()
        value = value.strip()

        if key in hashes:
            hashes[key] = value

    return hashes


def parse_alert(raw_json):

    if raw_json is None:
        return None

    if isinstance(raw_json, str):
        raw_json = raw_json.strip()

        if raw_json == "":
            return None

    try:

        if isinstance(raw_json, str):
            alert = json.loads(raw_json)
        else:
            alert = raw_json

        rule = alert.get("rule", {})

        system = (
            alert.get("data", {})
                 .get("win", {})
                 .get("system", {})
        )

        eventdata = (
            alert.get("data", {})
                 .get("win", {})
                 .get("eventdata", {})
        )

        return {

            # ===================================================
            # GENERAL
            # ===================================================

            "timestamp": alert.get("timestamp"),
            "location": alert.get("location"),
            "manager": alert.get("manager", {}).get("name"),

            # ===================================================
            # AGENT
            # ===================================================

            "agent_id": alert.get("agent", {}).get("id"),
            "agent_name": alert.get("agent", {}).get("name"),
            "agent_ip": alert.get("agent", {}).get("ip"),

            # ===================================================
            # RULE
            # ===================================================

            "rule_id": rule.get("id"),
            "severity": rule.get("level"),
            "description": rule.get("description"),
            "groups": rule.get("groups", []),

            # ===================================================
            # MITRE
            # ===================================================

            "mitre": rule.get("mitre", {}).get("id", []),
            "mitre_tactic": rule.get("mitre", {}).get("tactic", []),
            "mitre_technique": rule.get("mitre", {}).get("technique", []),

            # ===================================================
            # WINDOWS EVENT
            # ===================================================

            "event_id": system.get("eventID"),
            "provider": system.get("providerName"),
            "channel": system.get("channel"),
            "computer": system.get("computer"),
            "system_time": system.get("systemTime"),
            "event_record_id": system.get("eventRecordID"),
            "process_id": system.get("processID"),
            "thread_id": system.get("threadID"),
            "severity_value": system.get("severityValue"),

            # ===================================================
            # PROCESS
            # ===================================================

            "process_guid": eventdata.get("processGuid"),
            "process_id_sysmon": eventdata.get("processId"),

            "image": eventdata.get("image"),
            "image_loaded": eventdata.get("imageLoaded"),

            "command_line": eventdata.get("commandLine"),

            "current_directory": eventdata.get("currentDirectory"),

            "parent_image": eventdata.get("parentImage"),
            "parent_command": eventdata.get("parentCommandLine"),
            "parent_process_guid": eventdata.get("parentProcessGuid"),
            "parent_process_id": eventdata.get("parentProcessId"),

            # ===================================================
            # USER
            # ===================================================

            "user": eventdata.get("user"),
            "integrity_level": eventdata.get("integrityLevel"),
            "logon_guid": eventdata.get("logonGuid"),
            "logon_id": eventdata.get("logonId"),

            # ===================================================
            # FILE
            # ===================================================

            "target_filename": eventdata.get("targetFilename"),
            "creation_time": eventdata.get("creationUtcTime"),

            # ===================================================
            # HASHES
            # ===================================================

            "hashes": parse_hashes(
                eventdata.get("hashes")
            ),

            # ===================================================
            # SIGNATURE
            # ===================================================

            "signed": eventdata.get("signed"),
            "signature": eventdata.get("signature"),
            "signature_status": eventdata.get("signatureStatus"),

            # ===================================================
            # FILE INFO
            # ===================================================

            "file_version": eventdata.get("fileVersion"),
            "file_description": eventdata.get("description"),
            "product": eventdata.get("product"),
            "company": eventdata.get("company"),
            "original_file_name": eventdata.get("originalFileName"),

            # ===================================================
            # NETWORK
            # ===================================================

            "source_ip": eventdata.get("sourceIp"),
            "destination_ip": eventdata.get("destinationIp"),
            "source_port": eventdata.get("sourcePort"),
            "destination_port": eventdata.get("destinationPort"),
            "protocol": eventdata.get("protocol"),

            # ===================================================
            # DNS / URL
            # ===================================================

            "domain": eventdata.get("queryName"),
            "url": eventdata.get("url"),

            # ===================================================
            # EXTRA
            # ===================================================

            "rule_name": eventdata.get("ruleName"),
            "utc_time": eventdata.get("utcTime")

        }

    except json.JSONDecodeError:
        return None

    except Exception as e:
        print(f"[Parser Error] {e}")
        return None
