import hashlib
import json


class IncidentFingerprint:
    """
    Generates a deterministic SHA-256 fingerprint for an incident.

    The fingerprint is based only on fields that uniquely identify
    the security event and intentionally excludes dynamic fields
    such as report timestamps, UUIDs, or AI analysis.
    """

    @staticmethod
    def build(alert):
        """
        Build the normalized fingerprint dictionary.
        """

        hashes = alert.get("hashes", {})

        fingerprint = {

            # Core Wazuh Information
            "rule_id": alert.get("rule_id"),

            "agent_id": alert.get("agent_id"),

            "timestamp": alert.get("timestamp"),

            # Event Information
            "event_id": alert.get("event_id"),

            "process_guid": alert.get("process_guid"),

            "process_id": alert.get("process_id"),

            "image": alert.get("image"),

            "command_line": alert.get("command_line"),

            "parent_image": alert.get("parent_image"),

            # User
            "user": alert.get("user"),

            # Network
            "source_ip": alert.get("source_ip"),

            "destination_ip": alert.get("destination_ip"),

            "source_port": alert.get("source_port"),

            "destination_port": alert.get("destination_port"),

            "protocol": alert.get("protocol"),

            # File
            "target_filename": alert.get("target_filename"),

            # Hashes
            "md5": hashes.get("md5"),

            "sha1": hashes.get("sha1"),

            "sha256": hashes.get("sha256"),

            "imphash": hashes.get("imphash"),

            # MITRE
            # FIX: parser.py stores this under the key "mitre", not
            # "mitre_ids". The old code always hashed an empty list here,
            # so two incidents with different MITRE techniques (but the
            # same rule_id/image/etc.) could be treated as identical
            # for caching purposes when they shouldn't be.
            "mitre_ids": sorted(alert.get("mitre", []) or [])

        }

        return fingerprint

    @staticmethod
    def generate(alert):
        """
        Generate a SHA-256 fingerprint.
        """

        fingerprint = IncidentFingerprint.build(alert)

        serialized = json.dumps(
            fingerprint,
            sort_keys=True,
            separators=(",", ":")
        )

        digest = hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

        return digest
