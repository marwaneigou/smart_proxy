import re
import mitmproxy.http
from mitmproxy import ctx
from urllib.parse import urlparse

PHISHING_KEYWORDS = ["login", "secure", "account", "verify"]
SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"setTimeout\s*\(\s*['\"]?[A-Za-z0-9+/=]{8,}['\"]?\)",
]
REDIRECT_CODES = {301, 302}

class TrafficAnalyzer:
    def __init__(self, report):
        self.report = report

    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.pretty_url
        for keyword in PHISHING_KEYWORDS:
            if keyword in url.lower():
                ctx.log.warn(f"[Phishing URL Detected] {url}")
                self.report['phishing_urls'].append(url)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.pretty_url
        # Suspicious JS in HTML
        if "text/html" in flow.response.headers.get("content-type", ""):
            html = flow.response.text
            for pattern in SUSPICIOUS_JS_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    ctx.log.warn(f"[Suspicious JS Detected] {url} matches {pattern}")
                    self.report['suspicious_js'].append(url)
        # Unexpected redirects
        if flow.response.status_code in REDIRECT_CODES:
            loc = flow.response.headers.get("location", "")
            if loc:
                parsed = urlparse(loc)
                if parsed.netloc and not parsed.netloc.endswith("yourdomain.com"):
                    ctx.log.warn(f"[Unexpected Redirect] {url} -> {loc}")
                    self.report['unexpected_redirects'].append((url, loc))
        # SSL/TLS fingerprint mismatch (mitmproxy handles SSL, so this is simulated)
        if flow.server_conn and hasattr(flow.server_conn, 'certificate_list'):
            # In real world, compare fingerprint to known-good. Here, just log as example.
            pass  # Placeholder for actual fingerprint check

def load(l):
    if not hasattr(ctx, 'report'):
        ctx.report = {'phishing_urls': [], 'suspicious_js': [], 'unexpected_redirects': [], 'malware_found': [], 'downloads_scanned': 0}
    l.addons.add(TrafficAnalyzer(ctx.report))
