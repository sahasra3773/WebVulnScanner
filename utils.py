# utils.py
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("vuln_scanner")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler("vulnerabilities.log", maxBytes=5_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

def log_vulnerability(vuln_type: str, url: str, extra: str = "") -> None:
    logger.info("[%s] at %s %s", vuln_type, url, extra)
