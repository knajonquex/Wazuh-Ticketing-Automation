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


def send_email(report, html_file):
    """
    Send an HTML incident report via email.

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
        # Email Body
        # ---------------------------------------------------

        html_body = generate_email_html(report)

        message.attach(MIMEText(html_body, "html", "utf-8"))

        # ---------------------------------------------------
        # Attach the fully-styled standalone report too, so the
        # recipient can still open/save the richer browser version.
        # ---------------------------------------------------

        try:
            with open(html_file, "rb") as f:
                attachment = MIMEApplication(f.read(), _subtype="html")
                attachment.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=f"incident-{incident_id or 'report'}.html",
                )
                message.attach(attachment)
        except OSError as e:
            print(f"[Mailer] Could not attach full HTML report: {e}")

        # ---------------------------------------------------
        # Send Email
        # ---------------------------------------------------

        print("\n==============================")
        print("Sending Email...")
        print("==============================\n")

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

        print("Email sent successfully.")

        return True

    except Exception as e:

        print("\n========== EMAIL ERROR ==========\n")
        print(e)

        return False
