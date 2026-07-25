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

reader = AlertReader(WATCH_FILE)

class AlertHandler(FileSystemEventHandler):

    def on_modified(self, event):

        # We now watch the *directory*, so filter to our target file explicitly.
        if event.is_directory:
            return

        if os.path.abspath(event.src_path) != os.path.abspath(WATCH_FILE):
            return

        new_alerts = reader.read_new_alerts()
        print("[OK] New alert generated")
        for raw_alert in new_alerts:

            # Parse
            alert = parse_alert(raw_alert)
            print("[OK] Alert parsed")

            if alert is None:
                print("[Filters] Skipped: unparseable alert")
                continue

            alert = apply_filters(alert)

            if alert is None:
                print("[Filters] Skipped: did not meet severity/MITRE threshold")
                continue

            policy = evaluate_policy(alert)
            print("[OK] Policy evaluated")

            try:
                alert = enrich_alert(alert, policy)
                print("[OK] Threat intelligence completed")
            except Exception as e:
                print(f"[ThreatIntel Error] {e}")

            analysis = analyze_incident(alert)
            print("[OK] AI analysis completed")

            report = generate_report(alert, analysis)
            print("[OK] Report generated")

            html_file = generate_html_report(report)
            print(f"HTML Report saved to: {html_file}")

            if SEND_EMAIL:
                print("[*] Sending email notification...")

                if send_email(report, html_file):
                    print("[OK] Email sent successfully.")
                else:
                    print("[FAIL] Failed to send email.")
            else:
                print("[*] Email notification is disabled.")


observer = Observer()

watch_dir = WATCH_FILE

observer.schedule(
    AlertHandler(),
    path=watch_dir,
    recursive=True
)

observer.start()

print(f"Monitoring {WATCH_FILE} ...")

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    observer.stop()

observer.join()
