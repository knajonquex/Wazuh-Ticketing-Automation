"""
Threat Intelligence Orchestrator

Coordinates IOC enrichment using external threat intelligence services.
Currently supports:
    - VirusTotal (SHA256)
    - AbuseIPDB (IPv4)
"""

from integrations.virustotal import lookup_hash
from integrations.abuseipdb import lookup_ip
from logger import get_logger

logger = get_logger("threatintel")


def enrich_alert(alert, policy):
    """
    Enrich a parsed alert with threat intelligence.

    Parameters
    ----------
    alert : dict
        Parsed alert from parser.py

    policy : dict
        Output of evaluate_policy()

    Returns
    -------
    dict
        Alert with threat intelligence attached.
    """

    threat_intelligence = {}

    # --------------------------------------------------------
    # VirusTotal Lookup
    # --------------------------------------------------------

    if policy.get("lookup_hash"):

        hashes = alert.get("hashes", {})
        sha256 = hashes.get("sha256")

        if sha256:
            logger.info("Querying VirusTotal for SHA256: %s", sha256)

            vt_result = lookup_hash(sha256)

            threat_intelligence["virustotal"] = vt_result

    # --------------------------------------------------------
    # AbuseIPDB Lookup
    # --------------------------------------------------------

    if policy.get("lookup_ip"):

        ip = (
            alert.get("source_ip")
            or alert.get("destination_ip")
            or alert.get("agent_ip")
        )

        if ip:
            logger.info("Querying AbuseIPDB for IP: %s", ip)

            abuse_result = lookup_ip(ip)

            threat_intelligence["abuseipdb"] = abuse_result

    alert["threat_intelligence"] = threat_intelligence

    return alert
