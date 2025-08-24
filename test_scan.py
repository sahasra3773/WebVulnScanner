# test_scan.py
from crawler import crawl
from scanner import scan_target
from pathlib import Path

if __name__ == "__main__":
    target = "https://example.com"  # change to a local lab target you control
    cr = crawl(target)
    print("Crawl error:", cr.get("error"))
    print("Links:", len(cr.get("links", [])), "Forms:", len(cr.get("forms", [])))
    vulns, report = scan_target(target, cr)
    print("Vulns:", len(vulns))
    for v in vulns:
        print("-", v.name, v.severity, v.location)
    print("Report:", report, "exists:", Path(report).exists() if report else False)
