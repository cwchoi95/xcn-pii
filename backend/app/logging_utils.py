from __future__ import annotations

import logging
import os
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler


def setup_file_logging() -> None:
    if str(os.getenv("PII_FILE_LOG_ENABLED", "true")).strip().lower() not in ("1", "true", "yes", "on"):
        return

    log_dir = Path(os.getenv("PII_LOG_DIR", "/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "pii-api.log"
    level_name = str(os.getenv("PII_LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=int(os.getenv("PII_LOG_BACKUP_DAYS", "30")),
        encoding="utf-8",
        utc=False,
    )
    handler.suffix = "%Y-%m-%d"
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))

    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "pii.api", "pii.detect", "pii.engine", "pii.grpc"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        if not any(isinstance(h, TimedRotatingFileHandler) and getattr(h, "baseFilename", "") == str(log_file) for h in lg.handlers):
            lg.addHandler(handler)
        if name:
            lg.propagate = False
