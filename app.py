import os
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Create Flask app
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

# Secret key for sessions/flash messages
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# Reports folder
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Import scanner + crawler
try:
    from crawler import crawl
    from scanner import scan_target
except ImportError:
    def crawl(url):
        return {"forms": [], "links": []}
    def scan_target(url, crawl_result):
        return [], None


def is_valid_url(url: str) -> bool:
    """Check if URL is valid (http/https)."""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


# ------------------- Routes -------------------

@app.route("/", methods=["GET"])
def index():
    """Homepage with form."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def run_scan():
    """Run scan on submitted URL."""
    target = (request.form.get("url") or "").strip()
    if not is_valid_url(target):
        flash("❌ Please enter a valid URL (http:// or https://)")
        return redirect(url_for("index"))

    try:
        crawl_result = crawl(target)
        results, report_path = scan_target(target, crawl_result)
    except Exception as e:
        app.logger.exception("Scan failed for %s", target)
        flash("⚠️ Scan failed. Check server logs.")
        return redirect(url_for("index"))

    report_name = None
    if report_path:
        try:
            report_name = Path(report_path).name
        except Exception:
            report_name = None

    return render_template(
        "results.html",
        url=target,
        vulnerabilities=results or [],
        report_path=report_name
    )


@app.route("/reports/<name>")
def download_report(name):
    """Download saved report securely."""
    if Path(name).name != name:  # prevent path traversal
        abort(400, "Invalid report name")
    p = REPORTS_DIR / name
    if not p.exists():
        return "Report not found", 404
    return send_from_directory(str(REPORTS_DIR.resolve()), name, as_attachment=True)


# ------------------- Main -------------------
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
