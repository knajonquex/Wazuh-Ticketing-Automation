import requests

from config import (
    VIRUSTOTAL_API_KEY,
    VT_URL,
    REQUEST_TIMEOUT
)


def lookup_hash(hash_value):
    """
    Lookup a file hash in VirusTotal.

    Supports:
        - MD5
        - SHA1
        - SHA256

    Returns:
        dict
    """

    if not hash_value:
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    url = f"{VT_URL}/files/{hash_value}"

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 404:
            return {
                "found": False,
                "message": "Hash not found in VirusTotal"
            }

        if response.status_code == 401:
            return {
                "found": False,
                "error": "Invalid VirusTotal API Key"
            }

        if response.status_code == 429:
            return {
                "found": False,
                "error": "VirusTotal rate limit exceeded"
            }

        response.raise_for_status()

        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})

        return {

            "found": True,

            "hash": hash_value,

            "type": attributes.get("type_description"),

            "size": attributes.get("size"),

            "first_submission": attributes.get("first_submission_date"),

            "last_analysis": attributes.get("last_analysis_date"),

            "reputation": attributes.get("reputation"),

            "malicious": stats.get("malicious", 0),

            "suspicious": stats.get("suspicious", 0),

            "undetected": stats.get("undetected", 0),

            "harmless": stats.get("harmless", 0),

            "tags": attributes.get("tags", []),

            "names": attributes.get("names", []),

            "popular_threat_name":
                attributes.get("popular_threat_classification", {})
                          .get("suggested_threat_label"),

            "popular_category":
                attributes.get("popular_threat_classification", {})
                          .get("popular_threat_category", []),

            "popular_names":
                attributes.get("popular_threat_classification", {})
                          .get("popular_threat_name", []),

            "link":
                f"https://www.virustotal.com/gui/file/{hash_value}"
        }

    except requests.exceptions.Timeout:

        return {
            "found": False,
            "error": "VirusTotal request timed out"
        }

    except requests.exceptions.ConnectionError:

        return {
            "found": False,
            "error": "Unable to connect to VirusTotal"
        }

    except Exception as e:

        return {
            "found": False,
            "error": str(e)
        }
