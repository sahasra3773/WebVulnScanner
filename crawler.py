# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def same_origin(base, other):
    try:
        a, b = urlparse(base), urlparse(other)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)
    except Exception:
        return False

def crawl(url: str):
    """
    Crawl the target URL and return found links and forms.
    """
    out = {"links": [], "forms": []}
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return out
        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect links
        links = set()
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if same_origin(url, link):
                links.add(link)
        out["links"] = list(links)

        # Collect forms
        forms = []
        for f in soup.find_all("form"):
            action = f.get("action") or url
            method = (f.get("method") or "get").lower()
            inputs = [inp.get("name") for inp in f.find_all("input") if inp.get("name")]
            forms.append({
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs
            })
        out["forms"] = forms
    except Exception as e:
        print(f"[crawl error] {e}")
    return out
