"""
Centralized logging for the SOC automation pipeline.

Every module gets its own logger via get_logger(name), but they all
share the same two handlers -- console and a daily-rotating file under
LOG_DIRECTORY -- so the whole pipeline (alert received -> parsed ->
enriched -> fingerprinted -> cache checked -> analyzed -> reported ->
emailed) produces one consistent, timestamped, chronological record,
regardless of which module logged which line.

Usage, at the top of any module:

    from logger import get_logger
    logger = get_logger("monitor")   # use the module's own short name

    logger.info("Alert parsed")
    logger.warning("Alert skipped: did not meet severity/MITRE threshold")
    logger.error("Failed to send email")
    logger.exception("Ollama request failed")   # inside an except block --
                                                  # automatically attaches
                                                  # the traceback
"""

import logging
import logging.handlers
from pathlib import Path

from config import (
    LOG_LEVEL,
    LOG_DIRECTORY,
    LOG_FILENAME,
    LOG_RETENTION_DAYS,
)

_NAMESPACE = "soc"
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root_logger():
    global _configured

    if _configured:
        return

    log_dir = Path(LOG_DIRECTORY)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, str(LOG_LEVEL).upper(), logging.INFO)

    root = logging.getLogger(_NAMESPACE)
    root.setLevel(level)

    # Don't also hand records up to Python's bare root logger -- avoids
    # duplicate lines if some other library has called logging.basicConfig().
    root.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_dir / LOG_FILENAME,
        when="midnight",
        backupCount=LOG_RETENTION_DAYS,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    _configured = True


def get_logger(name):
    """
    Returns a logger under the shared "soc" namespace (e.g. "soc.monitor",
    "soc.mailer"). Configures the shared console + rotating file handlers
    on the very first call; every subsequent call just returns a child
    logger that feeds into those same handlers.

    Pass a short, explicit module name (e.g. "monitor", "mailer") rather
    than __name__ -- the entry-point script's __name__ is "__main__"
    when run directly, which would otherwise show up as "soc.__main__"
    in every log line from monitor.py.
    """
    _configure_root_logger()
    return logging.getLogger(f"{_NAMESPACE}.{name}")
