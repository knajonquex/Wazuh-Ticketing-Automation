import html
from pathlib import Path
from datetime import datetime, timezone


OUTPUT_DIR = Path("reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# (minimum rule level, label, color) â€” checked in order, first match wins
SEVERITY_LEVELS = [
    (15, "CRITICAL", "#9f1c2e"),
    (10, "HIGH", "#b6540b"),
    (7, "MEDIUM", "#a07d1b"),
    (0, "LOW", "#1f6b3d"),
]


def severity_info(level):
    """Returns (label, color_hex) for a numeric Wazuh rule level."""
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "UNKNOWN", "#5b6472"
    for threshold, label, color in SEVERITY_LEVELS:
        if level >= threshold:
            return label, color
    return "UNKNOWN", "#5b6472"


def esc(value, default="Not available"):
    """
    HTML-escapes a value before it goes into the report.
    Alert data (command lines, file paths, user names) is attacker-influenced
    and could contain '<', '&', or literal tags â€” escaping prevents that from
    breaking the report's markup or injecting anything into it.
    """
    if value is None or value == "":
        return default
    return html.escape(str(value))


def _row(label, value, mono=False):
    """Builds one <tr><th>label</th><td>value</td></tr>, escaped."""
    cls = ' class="mono"' if mono else ""
    return f"<tr><th>{esc(label, label)}</th><td{cls}>{esc(value)}</td></tr>"


def _list_items(items):
    """Builds <li> items for a list, or a placeholder if empty."""
    if not items:
        return "<li>No items recorded.</li>"
    return "".join(f"<li>{esc(item)}</li>" for item in items)


def _vt_summary(vt):
    """
    FIX: virustotal.py's lookup_hash() never returns "status", "total",
    or "threat_label" -- those keys didn't exist, so this section always
    rendered blank / "0 engines". It actually returns "found",
    "malicious"/"suspicious"/"undetected"/"harmless" counts, and
    "popular_threat_name". This derives the fields the template needs
    from what virustotal.py actually provides.
    """
    empty = {"status": None, "malicious": 0, "total": 0, "threat_label": None, "reputation": None}

    if not vt:
        return empty

    if vt.get("error"):
        return {**empty, "status": f"Error: {vt['error']}"}

    if not vt.get("found"):
        return {**empty, "status": "Not Found"}

    malicious = vt.get("malicious", 0) or 0
    suspicious = vt.get("suspicious", 0) or 0
    undetected = vt.get("undetected", 0) or 0
    harmless = vt.get("harmless", 0) or 0
    total = malicious + suspicious + undetected + harmless

    if malicious:
        status = "Malicious"
    elif suspicious:
        status = "Suspicious"
    else:
        status = "Clean"

    return {
        "status": status,
        "malicious": malicious,
        "total": total,
        "threat_label": vt.get("popular_threat_name"),
        "reputation": vt.get("reputation"),
    }


def generate_html_report(report):
    """
    Generates a formally formatted SOC incident report as a standalone HTML
    file and returns the path it was written to.
    """
    metadata = report.get("metadata", {})
    alert = report.get("alert", {})
    analysis = report.get("analysis", {})
    threat_intel = report.get("threat_intelligence", {})

    agent = alert.get("agent", {})
    rule = alert.get("rule", {})
    event = alert.get("event", {})
    network = alert.get("network", {})
    file_info = alert.get("file", {})
    hashes = file_info.get("hashes", {})
    mitre = alert.get("mitre", {})
    vt_raw = threat_intel.get("virustotal", {})
    vt = _vt_summary(vt_raw)
    abuse = threat_intel.get("abuseipdb", {}) or {}

    severity_label, severity_hex = severity_info(rule.get("level"))
    generated_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    mitre_ids = mitre.get("ids", []) or []
    mitre_tactics = mitre.get("tactics", []) or []
    mitre_techniques = mitre.get("techniques", []) or []

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Incident Report â€” {esc(metadata.get('incident_id'), 'Unknown')}</title>
<style>
 :root {{
   --ink:#1b2430;
   --paper:#eef1f6;
   --navy:#10213f;
   --slate:#2c4a7c;
   --rule:#d7dde6;
   --severity:{severity_hex};
 }}
 *{{ box-sizing:border-box; }}
 body{{
   background:var(--paper);
   font-family:"Segoe UI","Inter","Helvetica Neue",Arial,sans-serif;
   color:var(--ink);
   margin:0;
   padding:48px 20px;
   line-height:1.55;
 }}
 .sheet{{
   max-width:1160px;
   width:100%;
   margin:0 auto;
   background:#ffffff;
   border-left:6px solid var(--severity);
   box-shadow:0 1px 3px rgba(16,33,63,.08), 0 12px 32px rgba(16,33,63,.10);
   overflow:hidden;
 }}
 .classification{{
   background:var(--navy);
   color:#cfd8e8;
   text-align:center;
   font-family:"Consolas","SFMono-Regular","Liberation Mono",monospace;
   font-size:12px;
   letter-spacing:2px;
   text-transform:uppercase;
   padding:8px;
 }}
 .letterhead{{
   display:flex;
   justify-content:space-between;
   align-items:flex-start;
   flex-wrap:wrap;
   gap:16px;
   padding:32px 40px 24px;
   border-bottom:1px solid var(--rule);
 }}
 .letterhead h1{{
   font-family:Georgia,"Cambria","Times New Roman",serif;
   font-size:26px;
   margin:0 0 4px;
   color:var(--navy);
 }}
 .eyebrow{{
   font-size:12px;
   letter-spacing:1.5px;
   text-transform:uppercase;
   color:var(--slate);
   font-weight:600;
 }}
 .letterhead .meta{{
   text-align:right;
   font-family:"Consolas","SFMono-Regular",monospace;
   font-size:12.5px;
   color:#4b5568;
 }}
 .badge{{
   display:inline-block;
   margin-top:10px;
   background:var(--severity);
   color:#fff;
   padding:6px 16px;
   border-radius:3px;
   font-weight:700;
   font-size:12.5px;
   letter-spacing:1px;
 }}
 nav.toc{{
   margin:24px 40px;
   padding:18px 22px;
   background:var(--paper);
   border:1px solid var(--rule);
   border-radius:4px;
 }}
 nav.toc h2{{
   font-size:13px;
   letter-spacing:1.5px;
   text-transform:uppercase;
   color:var(--slate);
   margin:0 0 10px;
 }}
 nav.toc ol{{
   columns:2;
   margin:0;
   padding-left:18px;
   font-size:13.5px;
 }}
 nav.toc a{{ color:var(--ink); text-decoration:none; }}
 nav.toc a:hover{{ text-decoration:underline; }}
 section{{
   padding:26px 40px;
   border-bottom:1px solid var(--rule);
   page-break-inside:avoid;
 }}
 section:last-of-type{{ border-bottom:none; }}
 section h2{{
   font-family:Georgia,"Cambria","Times New Roman",serif;
   font-size:19px;
   color:var(--navy);
   margin:0 0 16px;
   display:flex;
   align-items:baseline;
   gap:10px;
 }}
 section h2 .n{{
   font-family:"Consolas","SFMono-Regular",monospace;
   font-size:13px;
   color:var(--slate);
   border:1px solid var(--slate);
   border-radius:3px;
   padding:1px 7px;
 }}
 h3.sub{{
   font-size:13.5px;
   text-transform:uppercase;
   letter-spacing:.5px;
   color:var(--slate);
   margin:18px 0 6px;
 }}
 h3.sub:first-of-type{{ margin-top:0; }}
 table{{ width:100%; border-collapse:collapse; font-size:14px; }}
 th{{
   background:var(--paper);
   color:var(--navy);
   text-align:left;
   padding:10px 14px;
   width:220px;
   border-bottom:1px solid var(--rule);
   font-weight:600;
   vertical-align:top;
 }}
 td{{
   padding:10px 14px;
   border-bottom:1px solid var(--rule);
   word-break:break-word;
   vertical-align:top;
 }}
 td.mono{{ font-family:"Consolas","SFMono-Regular","Liberation Mono",monospace; font-size:13px; }}
 .prose{{
   background:var(--paper);
   border-left:4px solid var(--slate);
   padding:18px 20px;
   font-size:14.5px;
   white-space:pre-wrap;
 }}
 ul,ol{{ margin:8px 0 0; padding-left:22px; }}
 li{{ margin-bottom:6px; font-size:14px; }}
 footer{{
   text-align:center;
   padding:22px;
   font-size:11.5px;
   color:#7a8494;
   font-family:"Consolas","SFMono-Regular",monospace;
 }}
 @media print{{
   body{{ padding:0; background:#fff; }}
   .sheet{{ box-shadow:none; }}
   nav.toc{{ display:none; }}
 }}
 @media (max-width:720px){{
   .letterhead{{ flex-direction:column; }}
   .letterhead .meta{{ text-align:left; }}
   nav.toc ol{{ columns:1; }}
   th{{ width:140px; }}
   section{{ padding:20px 22px; }}
   .letterhead{{ padding:24px 22px 20px; }}
 }}
</style>
</head>
<body>
<div class="sheet">

<div class="classification">TLP:AMBER &mdash; For Internal SOC Distribution Only</div>

<div class="letterhead">
  <div>
    <div class="eyebrow">Security Operations Center</div>
    <h1>Security Incident Report</h1>
    <span class="badge">{esc(severity_label, severity_label)}</span>
  </div>
  <div class="meta">
    Case&nbsp;ID: {esc(metadata.get('incident_id'), 'Unknown')}<br>
    Generated: {esc(metadata.get('generated_at'), generated_stamp)}<br>
    {esc(metadata.get('generator'), 'SOC Analyst')} v{esc(metadata.get('version'), '1.0')}
  </div>
</div>

<nav class="toc">
  <h2>Contents</h2>
  <ol>
    <li><a href="#s1">Executive Summary</a></li>
    <li><a href="#s2">Alert &amp; Agent Detail</a></li>
    <li><a href="#s3">Event Detail</a></li>
    <li><a href="#s4">Network Activity</a></li>
    <li><a href="#s5">File &amp; Hash Information</a></li>
    <li><a href="#s6">Threat Intelligence</a></li>
    <li><a href="#s7">Indicators of Compromise</a></li>
    <li><a href="#s8">MITRE ATT&amp;CK Mapping</a></li>
    <li><a href="#s9">Risk Assessment</a></li>
    <li><a href="#s10">Analyst Assessment</a></li>
    <li><a href="#s11">Investigation Findings</a></li>
    <li><a href="#s12">Response Actions</a></li>
    <li><a href="#s13">Recommendations &amp; Conclusion</a></li>
  </ol>
</nav>

<section id="s1">
  <h2><span class="n">01</span> Executive Summary</h2>
  <div class="prose">{esc(analysis.get('executive_summary'))}</div>
</section>

<section id="s2">
  <h2><span class="n">02</span> Alert &amp; Agent Detail</h2>
  <table>
    {_row("Timestamp", alert.get("timestamp"))}
    {_row("Detection Source", alert.get("manager"))}
    {_row("Agent", agent.get("name"))}
    {_row("Agent IP", agent.get("ip"), mono=True)}
    {_row("Rule ID", rule.get("id"))}
    {_row("Description", rule.get("description"))}
    {_row("Severity Level", rule.get("level"))}
  </table>
</section>

<section id="s3">
  <h2><span class="n">03</span> Event Detail</h2>
  <table>
    {_row("Event ID", event.get("event_id"))}
    {_row("Event Type", event.get("event_type"))}
    {_row("User", event.get("user"), mono=True)}
    {_row("Image", event.get("image"), mono=True)}
    {_row("Process ID", event.get("process_id"), mono=True)}
    {_row("Command Line", event.get("command_line"), mono=True)}
    {_row("Parent Image", event.get("parent_image"), mono=True)}
    {_row("Parent Command", event.get("parent_command_line"), mono=True)}
  </table>
</section>

<section id="s4">
  <h2><span class="n">04</span> Network Activity</h2>
  <table>
    {_row("Source IP", network.get("source_ip"), mono=True)}
    {_row("Source Port", network.get("source_port"), mono=True)}
    {_row("Destination IP", network.get("destination_ip"), mono=True)}
    {_row("Destination Port", network.get("destination_port"), mono=True)}
    {_row("Protocol", network.get("protocol"))}
  </table>
</section>

<section id="s5">
  <h2><span class="n">05</span> File &amp; Hash Information</h2>
  <table>
    {_row("Target File", file_info.get("target_filename"), mono=True)}
    {_row("Image Loaded", file_info.get("image_loaded"), mono=True)}
    {_row("MD5", hashes.get("md5"), mono=True)}
    {_row("SHA1", hashes.get("sha1"), mono=True)}
    {_row("SHA256", hashes.get("sha256"), mono=True)}
    {_row("IMPHASH", hashes.get("imphash"), mono=True)}
  </table>
</section>

<section id="s6">
  <h2><span class="n">06</span> Threat Intelligence</h2>
  <table>
    {_row("VirusTotal Status", vt.get("status"))}
    {_row("Detection Ratio", f"{vt.get('malicious', 0)} malicious / {vt.get('total', 0)} engines")}
    {_row("Threat Label", vt.get("threat_label"))}
    {_row("Reputation", vt.get("reputation"))}
    {_row("AbuseIPDB Confidence", f"{abuse.get('abuse_confidence_score', 'N/A')}%")}
    {_row("Country", abuse.get("country"))}
    {_row("ISP", abuse.get("isp"))}
    {_row("Total Reports", abuse.get("total_reports"))}
  </table>
</section>

<section id="s7">
  <h2><span class="n">07</span> Indicators of Compromise</h2>
  <table>
    <tr><th>Indicator</th><th>Value</th></tr>
    <tr><td>Agent IP</td><td class="mono">{esc(agent.get('ip'))}</td></tr>
    <tr><td>Source IP</td><td class="mono">{esc(network.get('source_ip'))}</td></tr>
    <tr><td>Destination IP</td><td class="mono">{esc(network.get('destination_ip'))}</td></tr>
    <tr><td>MD5</td><td class="mono">{esc(hashes.get('md5'))}</td></tr>
    <tr><td>SHA1</td><td class="mono">{esc(hashes.get('sha1'))}</td></tr>
    <tr><td>SHA256</td><td class="mono">{esc(hashes.get('sha256'))}</td></tr>
    <tr><td>Process</td><td class="mono">{esc(event.get('image'))}</td></tr>
    <tr><td>Command Line</td><td class="mono">{esc(event.get('command_line'))}</td></tr>
  </table>
</section>

<section id="s8">
  <h2><span class="n">08</span> MITRE ATT&amp;CK Mapping</h2>
  <table>
    <tr><th>Technique ID</th><th>Tactic</th><th>Technique</th></tr>
    <tr>
      <td class="mono">{"<br>".join(esc(x, x) for x in mitre_ids) or "Not available"}</td>
      <td>{"<br>".join(esc(x, x) for x in mitre_tactics) or "Not available"}</td>
      <td>{"<br>".join(esc(x, x) for x in mitre_techniques) or "Not available"}</td>
    </tr>
  </table>
</section>

<section id="s9">
  <h2><span class="n">09</span> Risk Assessment</h2>
  <table>
    {_row("Business Impact", analysis.get("business_impact"))}
    {_row("Threat Assessment", analysis.get("threat_assessment"))}
    {_row("Confidence", analysis.get("confidence"))}
    {_row("False Positive Likelihood", analysis.get("false_positive"))}
  </table>
</section>

<section id="s10">
  <h2><span class="n">10</span> Analyst Assessment</h2>
  <div class="prose">{esc(analysis.get('threat_assessment'), 'No assessment available.')}</div>
</section>

<section id="s11">
  <h2><span class="n">11</span> Investigation Findings</h2>
  <ul>
    <li>Detection Source: <strong>{esc(alert.get('manager'))}</strong></li>
    <li>Affected Agent: <strong>{esc(agent.get('name'))}</strong></li>
    <li>Rule Triggered: <strong>{esc(rule.get('description'))}</strong></li>
    <li>Event ID: <strong>{esc(event.get('event_id'))}</strong></li>
    <li>Executed Process: <strong>{esc(event.get('image'))}</strong></li>
    <li>User Context: <strong>{esc(event.get('user'))}</strong></li>
    <li>MITRE Techniques: <strong>{esc(", ".join(mitre_ids), "Not available")}</strong></li>
  </ul>
</section>

<section id="s12">
  <h2><span class="n">12</span> Response Actions</h2>
  <h3 class="sub">Containment</h3>
  <ol>{_list_items(analysis.get("containment", []))}</ol>
  <h3 class="sub">Eradication</h3>
  <ol>{_list_items(analysis.get("eradication", []))}</ol>
  <h3 class="sub">Recovery</h3>
  <ol>{_list_items(analysis.get("recovery", []))}</ol>
</section>

<section id="s13">
  <h2><span class="n">13</span> Recommendations &amp; Conclusion</h2>
  <h3 class="sub">Long-Term Recommendations</h3>
  <ol>{_list_items(analysis.get("recommendations", []))}</ol>
  <h3 class="sub">Analyst Conclusion</h3>
  <div class="prose">{esc(analysis.get('analyst_conclusion'), 'No conclusion available.')}</div>
</section>

<footer>
  Generated by SOC Analyst &middot; {esc(generated_stamp, generated_stamp)} &middot; Produced from Wazuh telemetry, threat-intelligence enrichment, and AI-assisted analysis. All findings require analyst review before containment or remediation actions are taken.
</footer>

</div>
</body>
</html>
"""

    filename = OUTPUT_DIR / f"{metadata.get('incident_id', 'report')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_doc)

    return filename


if __name__ == "__main__":
    sample_report = {
        "metadata": {
            "incident_id": "INC-2026-0417",
            "generated_at": "2026-07-22 09:12:00 UTC",
            "generator": "SOC-AI",
            "version": "2.1",
        },
        "alert": {
            "timestamp": "2026-07-17T20:01:02.597+0000",
            "manager": "Ubuntu-SRV",
            "agent": {"name": "Knajonquex", "ip": "192.168.0.5"},
            "rule": {"id": "92154", "description": "Process loaded taskschd.dll module.", "level": 12},
            "event": {
                "event_id": "7",
                "event_type": "Image Load",
                "user": "KNAJONQUEX\\baner",
                "image": "C:\\Windows\\SystemApps\\...\\SoftLandingTask.exe",
                "process_id": "18464",
                "command_line": "<script>alert(1)</script> --silent",
                "parent_image": "svchost.exe",
                "parent_command_line": "svchost.exe -k netsvcs",
            },
            "network": {
                "source_ip": "192.168.0.5",
                "source_port": "51322",
                "destination_ip": "51.68.10.4",
                "destination_port": "443",
                "protocol": "TCP",
            },
            "file": {
                "target_filename": "C:\\Windows\\Temp\\update.dll",
                "image_loaded": "C:\\Windows\\System32\\taskschd.dll",
                "hashes": {"md5": "DF9E41FF2CF7430B4A29B24BB86AB7B0", "sha1": "BF09E52...", "sha256": "1E3292A4...", "imphash": "E61FD409..."},
            },
            "mitre": {"ids": ["T1053.005"], "tactics": ["Execution", "Persistence"], "techniques": ["Scheduled Task"]},
        },
        "analysis": {
            "executive_summary": "Signed Microsoft process loaded Task Scheduler API; consistent with normal OS behavior.",
            "business_impact": "Low",
            "threat_assessment": "Likely benign, matches known Windows CBS task pattern.",
            "confidence": "0.85",
            "false_positive": "High likelihood",
            "containment": ["Isolate host if further indicators appear"],
            "eradication": ["No action required"],
            "recovery": ["Resume normal monitoring"],
            "recommendations": ["Tune rule 92154 to exclude known-benign SoftLandingTask.exe"],
            "analyst_conclusion": "Closed as false positive after review.",
        },
        "threat_intelligence": {
            "virustotal": {"status": "Clean", "malicious": 0, "total": 71, "threat_label": "None", "reputation": "Neutral"},
            "abuseipdb": {"abuse_confidence_score": 0, "country": "US", "isp": "Microsoft", "total_reports": 0},
        },
    }

    path = generate_html_report(sample_report)
    print(f"Report written to: {path.resolve()}")
