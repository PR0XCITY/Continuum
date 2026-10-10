"""Structured logging setup for Continuum.

Responsibility: configure a single logging setup (handlers, formatting,
log level, log file location under the configured data directory) that
every entry point calls once at startup instead of configuring logging
itself.

Hard rule enforced here: log records must never contain which keys were
pressed. Only timestamps, event types, per-session counters and device
identifiers may appear in any log line produced by this project. This
module does not enforce that by inspecting messages (there is nothing
to strip; no caller anywhere in Continuum ever has key content to log
in the first place), it just gives every entry point one consistent
place to log to.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_FILE_NAME = "continuum.log"
MAX_LOG_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3
ROOT_LOGGER_NAME = "continuum"

_configured = False


def configure_logging(
    *,
    level: str = "INFO",
    directory: Path,
) -> None:
    """Configure the root 'continuum' logger. Safe to call more than once;
    only the first call in a process actually attaches handlers.
    """
    global _configured
    if _configured:
        return

    directory.mkdir(parents=True, exist_ok=True)
    log_path = directory / LOG_FILE_NAME

    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter(LOG_FORMAT)

    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """A child of the 'continuum' logger. Works even before configure_logging()
    is called; records just queue on the root logger until it is.
    """
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


def _reset_for_tests() -> None:
    """Undo configure_logging() so tests can exercise it more than once."""
    global _configured
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    _configured = False
