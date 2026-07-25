import copy
import json
import re
import time
import requests

from cache import IncidentCache
from incident_fingerprint import IncidentFingerprint
from config import (
    OLLAMA_MODEL,
    OLLAMA_URL,
    OLLAMA_TIMEOUT
)

MODEL = OLLAMA_MODEL
CACHE = IncidentCache()

# ==========================================================
# Expected AI Response Schema
# ==========================================================

DEFAULT_ANALYSIS = {

    "executive_summary": "Not available.",

    "threat_assessment": "Not available.",

    "business_impact": "Not observed.",

    "false_positive": "Unknown",

    "confidence": "Unknown",

    "containment": [],

    "eradication": [],

    "recovery": [],

    "recommendations": [],

    "analyst_conclusion": "No conclusion.",

    "ioc_summary": "Not available.",

    "investigation_findings": [],

    "attack_probability": {

        "high": "",

        "medium": "",

        "low": ""
    }

}


# ==========================================================
# Prompt Builder
# ==========================================================

def build_prompt(alert):

    return f"""
You are a Senior SOC Analyst (Tier 2/Tier 3).

You investigate security incidents generated from SIEM telemetry.

The incident already contains:

- Wazuh Alert
- Sysmon Event Data
- MITRE ATT&CK Information
- Threat Intelligence
- Indicators of Compromise

Rules:

1. Base ALL conclusions ONLY on the supplied evidence.

2. Never invent data.

3. If something is missing write:

"Not observed."

4. Do NOT mention being an AI.

5. Do NOT use markdown.

6. Do NOT wrap JSON in ```.

7. Return ONLY valid JSON.

Return EXACTLY this schema:

{{
    "executive_summary":"",

    "threat_assessment":"",

    "business_impact":"",

    "false_positive":"",

    "confidence":"",

    "containment":[
        ""
    ],

    "eradication":[
        ""
    ],

    "recovery":[
        ""
    ],

    "recommendations":[
        ""
    ],

    "analyst_conclusion":"",

    "ioc_summary":"",

    "investigation_findings":[
        ""
    ],

    "attack_probability":{{
        "high":"",
        "medium":"",
        "low":""
    }}
}}

Incident Data:

{json.dumps(alert, indent=4)}
"""


# ==========================================================
# JSON Extraction
# ==========================================================

def extract_json(text):

    text = text.replace("```json", "")
    text = text.replace("```", "")

    match = re.search(r"\{.*\}", text, re.DOTALL)

    if match:
        return match.group(0)

    return None


# ==========================================================
# Ollama Request
# ==========================================================

def request_analysis(prompt):

    response = requests.post(

        OLLAMA_URL,

        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },

        timeout=OLLAMA_TIMEOUT
    )

    response.raise_for_status()

    return response.json()["response"]


# ==========================================================
# JSON Parsing
# ==========================================================

def parse_response(text):

    try:

        return json.loads(text)

    except Exception:

        extracted = extract_json(text)

        if extracted:

            return json.loads(extracted)

    raise ValueError("Unable to parse JSON response.")


# ==========================================================
# Retry Logic
# ==========================================================

def request_with_retry(prompt, retries=2):

    last_error = None

    for attempt in range(retries):

        try:

            raw = request_analysis(prompt)

            return parse_response(raw)

        except Exception as e:

            last_error = e

            time.sleep(2)

    raise last_error

# ==========================================================
# Merge AI Response with Default Schema
# ==========================================================

def merge_with_defaults(ai_response):
    """
    Merge the AI response with the default schema so that
    missing keys never break downstream modules.
    """

    result = copy.deepcopy(DEFAULT_ANALYSIS)

    for key, value in ai_response.items():

        if key == "attack_probability":

            probabilities = DEFAULT_ANALYSIS["attack_probability"].copy()

            if isinstance(value, dict):
                probabilities.update(value)

            result["attack_probability"] = probabilities

        else:
            result[key] = value

    return result


# ==========================================================
# Normalize Lists
# ==========================================================

def normalize_analysis(analysis):
    """
    Ensure list fields are always lists.
    """

    list_fields = [

        "containment",

        "eradication",

        "recovery",

        "recommendations",

        "investigation_findings"

    ]

    for field in list_fields:

        value = analysis.get(field)

        if value is None:

            analysis[field] = []

        elif isinstance(value, str):

            analysis[field] = [value]

        elif not isinstance(value, list):

            analysis[field] = [str(value)]

    return analysis


# ==========================================================
# Main Function
# ==========================================================

def analyze_incident(alert):
    """
    Analyze an enriched incident using Ollama.

    Before calling the LLM, check whether an identical
    incident has already been analyzed.
    """

    incident_hash = IncidentFingerprint.generate(alert)

    print("\n===================================================")
    print(f"Incident Fingerprint : {incident_hash}")
    print("===================================================\n")

    # --------------------------------------------------
    # Cache Lookup
    # --------------------------------------------------

    if CACHE.exists(incident_hash):

        print("Cache HIT")
        print("Loading cached AI analysis...\n")

        cached = CACHE.load(incident_hash)

        if cached is not None:

            return normalize_analysis(
                merge_with_defaults(cached)
            )

        print("Cache corrupted. Regenerating...\n")

    else:

        print("Cache MISS")
        print("Sending incident to Ollama...\n")

    # --------------------------------------------------
    # Ask Ollama
    # --------------------------------------------------

    prompt = build_prompt(alert)

    try:

        ai_response = request_with_retry(prompt)

        analysis = merge_with_defaults(ai_response)

        analysis = normalize_analysis(analysis)

        CACHE.save(
            incident_hash,
            analysis
        )

        print("Analysis cached successfully.\n")

        return analysis

    except Exception as e:

        print("\n================ OLLAMA ERROR ================\n")

        print(e)

        fallback = copy.deepcopy(DEFAULT_ANALYSIS)

        fallback["analyst_conclusion"] = str(e)

        return fallback
