"""
Email-safe HTML incident report.

html_report.py's output is great for opening as a standalone file in a
browser, but it relies on a <style> block, CSS variables, and flexbox --
all of which Gmail (and most other mail clients) strip out of received
HTML email for security/rendering reasons. Once that block is gone,
every class-based style reference goes with it, leaving bare unstyled
markup (which is exactly what shows up as "no table, no color, just
text").

Email clients need inline style="..." attributes on every element and
table-based layout. This module renders the same 13 sections as
html_report.py, but using that email-safe subset.
"""

from datetime import datetime, timezone

from html_report import severity_info, esc, _vt_summary

PAPER = "#eef1f6"
INK = "#1b2430"
NAVY = "#10213f"
SLATE = "#2c4a7c"
RULE = "#d7dde6"
MONO = 'font-family:"Consolas","Menlo","Liberation Mono",monospace;'


def _row(label, value, mono=False):
    font = f" {MONO} font-size:13px;" if mono else ""
    return f"""
    <tr>
      <th align="left" style="background:{PAPER}; color:{NAVY}; padding:10px 14px; width:190px; border-bottom:1px solid {RULE}; font-weight:600; font-size:14px; vertical-align:top; font-family:Arial,Helvetica,sans-serif;">{esc(label, label)}</th>
      <td style="padding:10px 14px; border-bottom:1px solid {RULE}; font-size:14px; vertical-align:top; font-family:Arial,Helvetica,sans-serif;{font}">{esc(value)}</td>
    </tr>"""


def _list_items(items):
    if not items:
        return f'<li style="margin-bottom:6px; font-size:14px; font-family:Arial,Helvetica,sans-serif;">No items recorded.</li>'
    return "".join(
        f'<li style="margin-bottom:6px; font-size:14px; font-family:Arial,Helvetica,sans-serif;">{esc(item)}</li>'
        for item in items
    )


def _section(number, title, inner_html):
    return f"""
  <tr>
    <td style="padding:24px 32px; border-bottom:1px solid {RULE};">
      <div style="font-family:Georgia,'Times New Roman',serif; font-size:18px; color:{NAVY}; margin:0 0 14px;">
        <span style="font-family:{MONO.split(':')[1].strip(';')}; font-size:12px; color:{SLATE}; border:1px solid {SLATE}; border-radius:3px; padding:1px 7px; margin-right:8px;">{number}</span>{title}
      </div>
      {inner_html}
    </td>
  </tr>"""


def generate_email_html(report):
    """
    Returns an HTML string suitable for use as an email body
    (inline styles, table layout, no <style> block, no CSS variables).
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

    vt = _vt_summary(threat_intel.get("virustotal", {}))
    abuse = threat_intel.get("abuseipdb", {}) or {}

    severity_label, severity_hex = severity_info(rule.get("level"))
    generated_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    mitre_ids = mitre.get("ids", []) or []
    mitre_tactics = mitre.get("tactics", []) or []
    mitre_techniques = mitre.get("techniques", []) or []

    F = 'font-family:Arial,Helvetica,sans-serif;'

    sections = []

    sections.append(_section("01", "Executive Summary", f"""
      <div style="background:{PAPER}; border-left:4px solid {SLATE}; padding:16px 18px; font-size:14px; {F} white-space:pre-wrap;">{esc(analysis.get('executive_summary'))}</div>
    """))

    sections.append(_section("02", "Alert &amp; Agent Detail", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("Timestamp", alert.get("timestamp"))}
        {_row("Detection Source", alert.get("manager"))}
        {_row("Agent", agent.get("name"))}
        {_row("Agent IP", agent.get("ip"), mono=True)}
        {_row("Rule ID", rule.get("id"))}
        {_row("Description", rule.get("description"))}
        {_row("Severity Level", rule.get("level"))}
      </table>
    """))

    sections.append(_section("03", "Event Detail", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("Event ID", event.get("event_id"))}
        {_row("Event Type", event.get("event_type"))}
        {_row("User", event.get("user"), mono=True)}
        {_row("Image", event.get("image"), mono=True)}
        {_row("Process ID", event.get("process_id"), mono=True)}
        {_row("Command Line", event.get("command_line"), mono=True)}
        {_row("Parent Image", event.get("parent_image"), mono=True)}
        {_row("Parent Command", event.get("parent_command_line"), mono=True)}
      </table>
    """))

    sections.append(_section("04", "Network Activity", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("Source IP", network.get("source_ip"), mono=True)}
        {_row("Source Port", network.get("source_port"), mono=True)}
        {_row("Destination IP", network.get("destination_ip"), mono=True)}
        {_row("Destination Port", network.get("destination_port"), mono=True)}
        {_row("Protocol", network.get("protocol"))}
      </table>
    """))

    sections.append(_section("05", "File &amp; Hash Information", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("Target File", file_info.get("target_filename"), mono=True)}
        {_row("Image Loaded", file_info.get("image_loaded"), mono=True)}
        {_row("MD5", hashes.get("md5"), mono=True)}
        {_row("SHA1", hashes.get("sha1"), mono=True)}
        {_row("SHA256", hashes.get("sha256"), mono=True)}
        {_row("IMPHASH", hashes.get("imphash"), mono=True)}
      </table>
    """))

    sections.append(_section("06", "Threat Intelligence", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("VirusTotal Status", vt.get("status"))}
        {_row("Detection Ratio", f"{vt.get('malicious', 0)} malicious / {vt.get('total', 0)} engines")}
        {_row("Threat Label", vt.get("threat_label"))}
        {_row("Reputation", vt.get("reputation"))}
        {_row("AbuseIPDB Confidence", f"{abuse.get('abuse_confidence_score', 'N/A')}%")}
        {_row("Country", abuse.get("country"))}
        {_row("ISP", abuse.get("isp"))}
        {_row("Total Reports", abuse.get("total_reports"))}
      </table>
    """))

    sections.append(_section("07", "Indicators of Compromise", f"""
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px; {F}">
        <tr><th align="left" style="background:{PAPER}; padding:8px 12px; border-bottom:1px solid {RULE};">Indicator</th><th align="left" style="background:{PAPER}; padding:8px 12px; border-bottom:1px solid {RULE};">Value</th></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">Agent IP</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(agent.get('ip'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">Source IP</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(network.get('source_ip'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">Destination IP</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(network.get('destination_ip'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">MD5</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(hashes.get('md5'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">SHA1</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(hashes.get('sha1'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">SHA256</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(hashes.get('sha256'))}</td></tr>
        <tr><td style="padding:8px 12px; border-bottom:1px solid {RULE};">Process</td><td style="padding:8px 12px; border-bottom:1px solid {RULE}; {MONO}">{esc(event.get('image'))}</td></tr>
        <tr><td style="padding:8px 12px;">Command Line</td><td style="padding:8px 12px; {MONO}">{esc(event.get('command_line'))}</td></tr>
      </table>
    """))

    sections.append(_section("08", "MITRE ATT&amp;CK Mapping", f"""
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px; {F}">
        <tr><th align="left" style="background:{PAPER}; padding:8px 12px; border-bottom:1px solid {RULE};">Technique ID</th><th align="left" style="background:{PAPER}; padding:8px 12px; border-bottom:1px solid {RULE};">Tactic</th><th align="left" style="background:{PAPER}; padding:8px 12px; border-bottom:1px solid {RULE};">Technique</th></tr>
        <tr>
          <td style="padding:8px 12px; {MONO}">{"<br>".join(esc(x, x) for x in mitre_ids) or "Not available"}</td>
          <td style="padding:8px 12px;">{"<br>".join(esc(x, x) for x in mitre_tactics) or "Not available"}</td>
          <td style="padding:8px 12px;">{"<br>".join(esc(x, x) for x in mitre_techniques) or "Not available"}</td>
        </tr>
      </table>
    """))

    sections.append(_section("09", "Risk Assessment", f"""
      <table width="100%" cellpadding="0" cellspacing="0">
        {_row("Business Impact", analysis.get("business_impact"))}
        {_row("Threat Assessment", analysis.get("threat_assessment"))}
        {_row("Confidence", analysis.get("confidence"))}
        {_row("False Positive Likelihood", analysis.get("false_positive"))}
      </table>
    """))

    sections.append(_section("10", "Analyst Assessment", f"""
      <div style="background:{PAPER}; border-left:4px solid {SLATE}; padding:16px 18px; font-size:14px; {F} white-space:pre-wrap;">{esc(analysis.get('threat_assessment'), 'No assessment available.')}</div>
    """))

    sections.append(_section("11", "Investigation Findings", f"""
      <ul style="margin:0; padding-left:20px;">
        <li style="margin-bottom:6px; font-size:14px; {F}">Detection Source: <strong>{esc(alert.get('manager'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">Affected Agent: <strong>{esc(agent.get('name'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">Rule Triggered: <strong>{esc(rule.get('description'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">Event ID: <strong>{esc(event.get('event_id'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">Executed Process: <strong>{esc(event.get('image'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">User Context: <strong>{esc(event.get('user'))}</strong></li>
        <li style="margin-bottom:6px; font-size:14px; {F}">MITRE Techniques: <strong>{esc(", ".join(mitre_ids), "Not available")}</strong></li>
      </ul>
    """))

    sections.append(_section("12", "Response Actions", f"""
      <div style="font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:{SLATE}; {F} margin-bottom:6px;">Containment</div>
      <ol style="margin:0 0 16px; padding-left:20px;">{_list_items(analysis.get("containment", []))}</ol>
      <div style="font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:{SLATE}; {F} margin-bottom:6px;">Eradication</div>
      <ol style="margin:0 0 16px; padding-left:20px;">{_list_items(analysis.get("eradication", []))}</ol>
      <div style="font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:{SLATE}; {F} margin-bottom:6px;">Recovery</div>
      <ol style="margin:0; padding-left:20px;">{_list_items(analysis.get("recovery", []))}</ol>
    """))

    sections.append(_section("13", "Recommendations &amp; Conclusion", f"""
      <div style="font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:{SLATE}; {F} margin-bottom:6px;">Long-Term Recommendations</div>
      <ol style="margin:0 0 16px; padding-left:20px;">{_list_items(analysis.get("recommendations", []))}</ol>
      <div style="font-size:13px; text-transform:uppercase; letter-spacing:.5px; color:{SLATE}; {F} margin-bottom:6px;">Analyst Conclusion</div>
      <div style="background:{PAPER}; border-left:4px solid {SLATE}; padding:16px 18px; font-size:14px; {F} white-space:pre-wrap;">{esc(analysis.get('analyst_conclusion'), 'No conclusion available.')}</div>
    """))

    body = "\n".join(sections)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Incident Report</title>
</head>
<body style="margin:0; padding:0; background:{PAPER};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{PAPER};">
<tr><td align="center" style="padding:32px 16px;">

<table role="presentation" width="680" cellpadding="0" cellspacing="0" style="background:#ffffff; border-left:6px solid {severity_hex};">

  <tr>
    <td style="background:{NAVY}; color:#cfd8e8; text-align:center; {MONO} font-size:12px; letter-spacing:2px; text-transform:uppercase; padding:8px;">TLP:AMBER &mdash; For Internal SOC Distribution Only</td>
  </tr>

  <tr>
    <td style="padding:28px 32px 20px; border-bottom:1px solid {RULE};">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td valign="top">
            <div style="font-size:12px; letter-spacing:1.5px; text-transform:uppercase; color:{SLATE}; font-weight:600; {F}">Security Operations Center</div>
            <div style="font-family:Georgia,'Times New Roman',serif; font-size:24px; color:{NAVY}; margin:4px 0 10px;">Security Incident Report</div>
            <span style="display:inline-block; background:{severity_hex}; color:#ffffff; padding:6px 16px; border-radius:3px; font-weight:700; font-size:12px; letter-spacing:1px; {F}">{esc(severity_label, severity_label)}</span>
          </td>
          <td valign="top" align="right" style="{MONO} font-size:12px; color:#4b5568;">
            Case ID: {esc(metadata.get('incident_id'), 'Unknown')}<br>
            Generated: {esc(metadata.get('generated_at'), generated_stamp)}<br>
            {esc(metadata.get('generator'), 'SOC Analyst')} v{esc(metadata.get('version'), '1.0')}
          </td>
        </tr>
      </table>
    </td>
  </tr>

  {body}

  <tr>
    <td align="center" style="padding:20px; font-size:11px; color:#7a8494; {MONO}">
      Generated by SOC Analyst &middot; {esc(generated_stamp, generated_stamp)}<br>
      Produced from Wazuh telemetry, threat-intelligence enrichment, and AI-assisted analysis.<br>
      All findings require analyst review before containment or remediation actions are taken.
    </td>
  </tr>

</table>

</td></tr>
</table>
</body>
</html>
"""

    return html_doc
