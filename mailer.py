import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import make_msgid

from config import (
    SMTP_SERVER,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    FROM_EMAIL,
    TO_EMAIL,
)

from email_report import generate_email_html
from raw_alert import save_raw_alert
from logger import get_logger

logger = get_logger("mailer")


def send_email(report, raw_alert):
    """
    Send an HTML incident report via email.

    Args:
        report (dict): Structured incident report.
        raw_alert (str): The original, unmodified raw Wazuh alert JSON
                          line (as read from alerts.json, before parsing).
                          Saved to disk and attached as a .json file so
                          the recipient has the original evidence, rather
                          than attaching the styled HTML report.

    Returns:
        bool
    """

    alert_data = report.get("alert", {})
    rule = alert_data.get("rule", {})
    metadata = report.get("metadata", {})

    rule_level = rule.get("level", "N/A")
    rule_description = rule.get("description", "Security Incident Report")

    incident_id = metadata.get("incident_id", "")
    case_suffix = f" [Case {incident_id[:8]}]" if incident_id else ""

    subject = f"[{rule_level}] {rule_description}{case_suffix}"

    try:

        message = MIMEMultipart()

        message["From"] = FROM_EMAIL
        message["To"] = TO_EMAIL
        message["Subject"] = subject
        message["Message-ID"] = make_msgid()

        # ---------------------------------------------------
        # Email Body (inline-styled, table-based -- see email_report.py)
        # ---------------------------------------------------

        html_body = generate_email_html(report)

        message.attach(MIMEText(html_body, "html", "utf-8"))

        # ---------------------------------------------------
        # Attach the raw alert instead of the styled HTML report.
        # Saved to disk first (so it's kept as a permanent record
        # alongside the rest of the reports), then attached.
        # ---------------------------------------------------

        try:
            raw_alert_path = save_raw_alert(raw_alert, incident_id or "unknown")

            with open(raw_alert_path, "rb") as f:
                attachment = MIMEApplication(f.read(), _subtype="json")
                attachment.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=f"raw-alert-{incident_id or 'unknown'}.json",
                )
                message.attach(attachment)

        except OSError as e:
            logger.warning("Could not save/attach raw alert (incident_id=%s): %s", incident_id, e)

        # ---------------------------------------------------
        # Send Email
        # ---------------------------------------------------

        logger.info("Sending email (incident_id=%s, subject=%r)", incident_id, subject)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:

            smtp.starttls()

            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            )

            smtp.sendmail(
                FROM_EMAIL,
                TO_EMAIL,
                message.as_string()
            )

        logger.info("Email sent successfully (incident_id=%s)", incident_id)

        return True

    except Exception:

        logger.exception("Failed to send email (incident_id=%s)", incident_id)

        return False
