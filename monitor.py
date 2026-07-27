import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from reader import AlertReader
from parser import parse_alert
from filters import apply_filters
from policy_engine import evaluate_policy
from threatintel import enrich_alert
from ollama_ai import analyze_incident
from report import generate_report
from html_report import generate_html_report
from mailer import send_email
from config import WATCH_FILE, SEND_EMAIL
from logger import get_logger

logger = get_logger("monitor")

logger.info("All modules imported.")

reader = AlertReader(WATCH_FILE)


class AlertHandler(FileSystemEventHandler):

    def on_modified(self, event):

        if event.is_directory:
            return

        if os.path.abspath(event.src_path) != os.path.abspath(WATCH_FILE):
            return

        new_alerts = reader.read_new_alerts()
        logger.debug("Read %d new raw alert(s): %r", len(new_alerts), new_alerts)

        for raw_alert in new_alerts:

            alert = parse_alert(raw_alert)

            if alert is None:
                logger.warning("Alert skipped: unparseable raw alert: %r", raw_alert)
                continue

            logger.info("Alert parsed (rule_id=%s)", alert.get("rule_id"))

            alert = apply_filters(alert)

            if alert is None:
                logger.info("Alert skipped: did not meet severity/MITRE threshold")
                continue

            policy = evaluate_policy(alert)
            logger.info("Policy evaluated")

            try:
                alert = enrich_alert(alert, policy)
                logger.info("Threat intelligence enrichment completed")
            except Exception:
                logger.exception("Threat intelligence enrichment failed")

            analysis = analyze_incident(alert)
            logger.info("AI analysis completed")

            report = generate_report(alert, analysis)
            incident_id = report.get("metadata", {}).get("incident_id")
            logger.info("Report generated (incident_id=%s)", incident_id)

            html_file = generate_html_report(report)
            logger.info("HTML report saved to disk: %s", html_file)

            if SEND_EMAIL:
                logger.info("Sending email notification (incident_id=%s)", incident_id)

                if send_email(report, raw_alert):
                    logger.info("Email sent successfully (incident_id=%s)", incident_id)
                else:
                    logger.error("Failed to send email (incident_id=%s)", incident_id)
            else:
                logger.debug("Email notification is disabled; skipping send")


observer = Observer()

watch_dir = os.path.dirname(WATCH_FILE) or "."

observer.schedule(
    AlertHandler(),
    path=watch_dir,
    recursive=False
)

observer.start()

logger.info("Monitoring started: %s", WATCH_FILE)

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    logger.info("Shutdown requested (KeyboardInterrupt). Stopping observer...")
    observer.stop()

observer.join()
logger.info("Monitor stopped cleanly.")
