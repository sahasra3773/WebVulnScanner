# scanner.py — full working version compatible with:
# results, report_path = scan_target(target, crawl_result)

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urljoin, unquote_plus

import html
import requests

# ---------------------------
# Payloads (robust import + fallbacks)
# ---------------------------
try:
    # If you have a top-level payloads.py
    from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, COMMON_PARAM_NAMES
except Exception:
    try:
        # If you put payloads/payloads.py in a package directory
        from payloads.payloads import SQLI_PAYLOADS, XSS_PAYLOADS, COMMON_PARAM_NAMES  # type: ignore
    except Exception:
        # Fallback defaults (keep simple/safe)
        SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
        XSS_PAYLOADS = ["<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>"]
        COMMON_PARAM_NAMES = ["q", "query", "search", "id", "name", "s"]

# ---------------------------
# Vulnerability model (import or fallback)
# ---------------------------
try:
    from vulnerabilities import Vulnerability  # your own dataclass
except Exception:
    @dataclass
    class Vulnerability:
        name: str
        description: str
        severity: str  # "High" | "Medium" | "Low" | "Info"
        evidence: str
        location: str

        def to_dict(self):
            return {
                "name": self.name,
                "description": self.description,
                "severity": self.severity,
                "evidence": self.evidence,
                "location": self.location,
            }

# ---------------------------
# Logging / HTTP session
# ---------------------------
logger = logging.getLogger("scanner")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "WebVulnScanner/1.0 (+edu)"})
TIMEOUT = 10

# Regex to detect common SQL error traces
SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql|mysqli|psql|postgres|sqlite|oracle|odbc|jdbc|"
    r"unterminated|unclosed|unexpected end of SQL|ORA-\d+|You have an error in your SQL)",
    re.IGNORECASE,
)

# ---------------------------
# Helpers
# ---------------------------
def _is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def _same_origin(base: str, other: str) -> bool:
    try:
        a, b = urlparse(base), urlparse(other)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)
    except Exception:
        return False

def _safe_get(u: str, params=None):
    try:
        return SESSION.get(u, params=params, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.debug("GET %s failed: %s", u, e)
        return None

def _safe_post(u: str, data=None):
    try:
        return SESSION.post(u, data=data, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.debug("POST %s failed: %s", u, e)
        return None

def _resp_text(resp) -> str:
    if not resp:
        return ""
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    try:
        return html.unescape(unquote_plus(text))
    except Exception:
        return html.unescape(text)

def _check_sqli(resp) -> bool:
    if not resp:
        return False
    return bool(SQLI_ERRORS.search(_resp_text(resp)))

def _check_xss_echo(resp, payload: str) -> bool:
    if not resp:
        return False
    text = _resp_text(resp)
    if payload in text:
        return True
    try:
        return html.unescape(payload) in text
    except Exception:
        return False

def _save_report(url: str, vulns: List[Vulnerability]) -> Path:
    outdir = Path("reports")
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"report-{stamp}-{uuid.uuid4().hex[:8]}.json"
    path = outdir / name
    payload = {
        "target": url,
        "count": len(vulns),
        "vulnerabilities": [v.to_dict() for v in vulns],
        "generated_at": stamp,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

# ---------------------------
# Scanning logic
# ---------------------------
def _scan_get_params(url: str) -> List[Vulnerability]:
    """Try injecting payloads into common query parameters."""
    vulns: List[Vulnerability] = []
    for pname in COMMON_PARAM_NAMES:
        # SQLi
        for payload in SQLI_PAYLOADS:
            r = _safe_get(url, params={pname: payload})
            if r and _check_sqli(r):
                vulns.append(
                    Vulnerability(
                        "SQL Injection",
                        f"DB error pattern after GET injection into '{pname}'.",
                        "High",
                        f"{pname}={payload}",
                        r.url or url,
                    )
                )
        # XSS
        for payload in XSS_PAYLOADS:
            r = _safe_get(url, params={pname: payload})
            if r and _check_xss_echo(r, payload):
                vulns.append(
                    Vulnerability(
                        "Cross-Site Scripting (XSS)",
                        f"Reflected payload after GET injection into '{pname}'.",
                        "Medium",
                        f"{pname}={payload}",
                        r.url or url,
                    )
                )
    return vulns

def _scan_forms(forms: List[Dict], base_url: str) -> List[Vulnerability]:
    """Submit payloads to discovered forms (same-origin only)."""
    vulns: List[Vulnerability] = []
    for f in forms or []:
        action = f.get("action") or base_url
        method = (f.get("method") or "get").lower()
        inputs = list(f.get("inputs") or [])

        # Normalize and guard
        action = urljoin(base_url, action)
        if not _is_http_url(action):
            continue
        if not _same_origin(base_url, action):
            # avoid SSRF
            logger.info("Skip non-same-origin form action: %s", action)
            continue
        if not inputs:
            continue

        target_field = inputs[0]  # pick first input to keep noise down

        # SQLi via form
        for payload in SQLI_PAYLOADS:
            data = {n: (payload if n == target_field else "test") for n in inputs}
            r = _safe_post(action, data=data) if method == "post" else _safe_get(action, params=data)
            if r and _check_sqli(r):
                vulns.append(
                    Vulnerability(
                        "SQL Injection",
                        f"DB error after {method.upper()} form submit.",
                        "High",
                        f"{target_field}={payload}",
                        action,
                    )
                )

        # XSS via form
        for payload in XSS_PAYLOADS:
            data = {n: (payload if n == target_field else "test") for n in inputs}
            r = _safe_post(action, data=data) if method == "post" else _safe_get(action, params=data)
            if r and _check_xss_echo(r, payload):
                vulns.append(
                    Vulnerability(
                        "Cross-Site Scripting (XSS)",
                        f"Reflected payload after {method.upper()} form submit.",
                        "Medium",
                        f"{target_field}={payload}",
                        action,
                    )
                )

        # Heuristic CSRF check: POST form without a token-like field
        if method == "post":
            token_names = {"csrf", "_csrf", "csrfmiddlewaretoken", "authenticity_token"}
            has_token = any(n.lower() in token_names for n in inputs)
            if not has_token:
                vulns.append(
                    Vulnerability(
                        "Possible CSRF Missing Token",
                        "POST form without an apparent CSRF token (heuristic).",
                        "Low",
                        f"fields={inputs}",
                        action,
                    )
                )

    return vulns

# ---------------------------
# Public API used by app.py
# ---------------------------
def scan_target(url: str, crawl_result: Dict) -> Tuple[List[Vulnerability], Path]:
    """
    Main entry point for Flask: accepts the target URL and the crawl_result
    returned by crawler.crawl(url). Returns (vulnerabilities, report_path).
    """
    vulns: List[Vulnerability] = []

    # 1) Try light GET parameter fuzzing on the base URL
    try:
        vulns.extend(_scan_get_params(url))
    except Exception as e:
        logger.exception("GET param scan failed for %s: %s", url, e)

    # 2) Use discovered forms from the crawl
    try:
        forms = []
        if isinstance(crawl_result, dict):
            forms = crawl_result.get("forms") or []
        vulns.extend(_scan_forms(forms, url))
    except Exception as e:
        logger.exception("Form scan failed for %s: %s", url, e)

    # 3) Save JSON report
    report_path = _save_report(url, vulns)

    return vulns, report_path
