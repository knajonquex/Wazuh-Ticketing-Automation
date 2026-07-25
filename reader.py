import os


class AlertReader:

    def __init__(self, file_path):

        self.file_path = file_path

        with open(self.file_path, "r") as f:
            f.seek(0, os.SEEK_END)
            self.position = f.tell()

    def read_new_alerts(self):

        alerts = []

        with open(self.file_path, "r") as f:

            f.seek(self.position)

            while True:

                line = f.readline()

                # EOF
                if not line:
                    break

                # Wazuh still writing
                if not line.endswith("\n"):

                    f.seek(f.tell() - len(line))
                    break

                line = line.strip()

                # Ignore blank lines
                if not line:
                    continue

                # Ignore malformed lines
                if not line.startswith("{"):
                    continue

                alerts.append(line)

            self.position = f.tell()

        return alerts
