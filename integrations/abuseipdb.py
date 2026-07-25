import requests

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_URL,
    REQUEST_TIMEOUT
)


def lookup_ip(ip_address):
    """
    Lookup an IP address in AbuseIPDB.

    Returns:
        dict
    """

    if not ip_address:
        return None

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": True
    }

    url = f"{ABUSEIPDB_URL}/check"

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 401:
            return {
                "found": False,
                "error": "Invalid AbuseIPDB API Key"
            }

        if response.status_code == 404:
            return {
                "found": False,
                "error": "IP Address not found"
            }

        if response.status_code == 429:
            return {
                "found": False,
                "error": "AbuseIPDB rate limit exceeded"
            }

        response.raise_for_status()

        data = response.json().get("data", {})

        return {

            "found": True,

            "ip": data.get("ipAddress"),

            "abuse_confidence_score":
                data.get("abuseConfidenceScore"),

            "country":
                data.get("countryCode"),

            "country_name":
                data.get("countryName"),

            "isp":
                data.get("isp"),

            "domain":
                data.get("domain"),

            "hostnames":
                data.get("hostnames", []),

            "usage_type":
                data.get("usageType"),

            "is_public":
                data.get("isPublic"),

            "is_whitelisted":
                data.get("isWhitelisted"),

            "is_tor":
                data.get("isTor"),

            "total_reports":
                data.get("totalReports"),

            "distinct_users":
                data.get("numDistinctUsers"),

            "last_reported":
                data.get("lastReportedAt"),

            "link":
                f"https://www.abuseipdb.com/check/{ip_address}"
        }

    except requests.exceptions.Timeout:

        return {
            "found": False,
            "error": "AbuseIPDB request timed out"
        }

    except requests.exceptions.ConnectionError:

        return {
            "found": False,
            "error": "Unable to connect to AbuseIPDB"
        }

    except Exception as e:

        return {
            "found": False,
            "error": str(e)
        }
