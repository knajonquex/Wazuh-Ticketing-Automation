from config import (
    ENABLE_POLICY_ENGINE,
    ENABLE_AI_ANALYSIS,
    ENABLE_THREAT_INTEL,
    GENERATE_REPORT,
    GENERATE_HTML_REPORT,
    SEND_EMAIL,
    LOOKUP_IP,
    LOOKUP_HASH,
    LOOKUP_DOMAIN,
    LOOKUP_URL
)


def evaluate_policy(alert):
    """
    Decide how this alert should be processed.

    Returns a dictionary describing which modules
    should execute for this alert.
    """

    policy = {

        "process": True,

        "run_ai": False,

        "run_threat_intel": False,

        "lookup_ip": False,

        "lookup_hash": False,

        "lookup_domain": False,

        "lookup_url": False,

        "generate_report": False,

        "generate_html": False,

        "send_email": False
    }

    if not ENABLE_POLICY_ENGINE:
        return policy

    # --------------------------------------------------
    # AI Analysis
    # --------------------------------------------------

    if ENABLE_AI_ANALYSIS:
        policy["run_ai"] = True

    # --------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------

    if ENABLE_THREAT_INTEL:

        policy["run_threat_intel"] = True

        # IOC Based Decisions

        if LOOKUP_IP and alert.get("agent_ip"):
            policy["lookup_ip"] = True

        hashes = alert.get("hashes", {})

        if LOOKUP_HASH and hashes.get("sha256"):
            policy["lookup_hash"] = True

        if LOOKUP_DOMAIN and alert.get("domain"):
            policy["lookup_domain"] = True

        if LOOKUP_URL and alert.get("url"):
            policy["lookup_url"] = True

    # --------------------------------------------------
    # Reporting
    # --------------------------------------------------

    if GENERATE_REPORT:
        policy["generate_report"] = True

    if GENERATE_HTML_REPORT:
        policy["generate_html"] = True

    if SEND_EMAIL:
        policy["send_email"] = True

    return policy
