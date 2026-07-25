import uuid
from datetime import datetime, timezone

# --------------------------------------------------------------------
# This maps the common Sysmon channel event
# --------------------------------------------------------------------
SYSMON_EVENT_TYPES = {
    "1": "Process Creation",
    "2": "File Creation Time Changed",
    "3": "Network Connection",
    "4": "Sysmon Service State Changed",
    "5": "Process Terminated",
    "6": "Driver Loaded",
    "7": "Image Loaded",
    "8": "CreateRemoteThread",
    "9": "RawAccessRead",
    "10": "Process Access",
    "11": "File Created",
    "12": "Registry Object Added/Deleted",
    "13": "Registry Value Set",
    "14": "Registry Object Renamed",
    "15": "File Stream Created",
    "16": "Sysmon Config State Changed",
    "17": "Pipe Created",
    "18": "Pipe Connected",
    "19": "WMI Filter",
    "20": "WMI Consumer",
    "21": "WMI Consumer Filter",
    "22": "DNS Query",
    "23": "File Delete",
    "24": "Clipboard Change",
    "25": "Process Tampering",
    "26": "File Delete Logged",
}


def _event_type(alert):
    return SYSMON_EVENT_TYPES.get(str(alert.get("event_id")), "Unknown")


def generate_report(alert, analysis):
    """
    Generate a standardized SOC incident object.

    This object is the canonical representation of an incident and can
    later be rendered into HTML, PDF, email, or ticketing systems.
    """

    report = {

        # ==========================================================
        # REPORT METADATA
        # ==========================================================

        "metadata": {

            "incident_id": str(uuid.uuid4()),

            "generated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),

            "generator": "Knajonquex SOC Automation",

            "version": "1.0"
        },

        # ==========================================================
        # ALERT INFORMATION
        # ==========================================================

        "alert": {

            "timestamp": alert.get("timestamp"),

            "manager": alert.get("manager"),

            "agent": {

                "id": alert.get("agent_id"),

                "name": alert.get("agent_name"),

                "ip": alert.get("agent_ip")
            },

            "rule": {

                "id": alert.get("rule_id"),

                "description": alert.get("description"),

                "level": alert.get("severity"),

                "groups": alert.get("groups", [])
            },

            "mitre": {

                "ids": alert.get("mitre", []),

                "tactics": alert.get("mitre_tactic", []),

                "techniques": alert.get("mitre_technique", [])
            },

            "event": {

                "event_id": alert.get("event_id"),

                "event_type": _event_type(alert),

                "process_guid": alert.get("process_guid"),

                "process_id": alert.get("process_id_sysmon") or alert.get("process_id"),

                "image": alert.get("image"),

                "command_line": alert.get("command_line"),

                "current_directory": alert.get("current_directory"),

                "parent_image": alert.get("parent_image"),

                "parent_command_line": alert.get("parent_command"),

                "user": alert.get("user")
            },

            "network": {

                "source_ip": alert.get("source_ip"),

                "source_port": alert.get("source_port"),

                "destination_ip": alert.get("destination_ip"),

                "destination_port": alert.get("destination_port"),

                "protocol": alert.get("protocol")
            },

            "file": {

                "target_filename": alert.get("target_filename"),

                "image_loaded": alert.get("image_loaded"),

                "hashes": alert.get("hashes", {})
            }
        },

        # ==========================================================
        # THREAT INTELLIGENCE
        # ==========================================================

        "threat_intelligence": alert.get(
            "threat_intelligence",
            {}
        ),

        # ==========================================================
        # AI ANALYSIS
        # ==========================================================

        "analysis": {

            "executive_summary":
                analysis.get("executive_summary"),

            "threat_assessment":
                analysis.get("threat_assessment"),

            "business_impact":
                analysis.get("business_impact"),

            "false_positive":
                analysis.get("false_positive"),

            "containment":
                analysis.get("containment", []),

            "eradication":
                analysis.get("eradication", []),

            "recovery":
                analysis.get("recovery", []),

            "recommendations":
                analysis.get("recommendations", []),

            "analyst_conclusion":
                analysis.get("analyst_conclusion"),

            "confidence":
                analysis.get("confidence")
        }

    }

    return report
