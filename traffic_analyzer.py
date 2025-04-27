import re
import mitmproxy.http
from mitmproxy import ctx
from urllib.parse import urlparse
from mitmproxy import http  # Needed for blocking responses

# Import dashboard if available
try:
    import dashboard
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False

PHISHING_KEYWORDS = ["login", "secure", "account", "verify"]
SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"setTimeout\s*\(\s*['\"]?[A-Za-z0-9+/=]{8,}['\"]?\)",
]
REDIRECT_CODES = {301, 302}

class TrafficAnalyzer:
    def __init__(self, report, config=None):
        self.report = report
        self.config = config or {}

    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.pretty_url
        # User-Agent/referrer inspection
        ua = flow.request.headers.get('user-agent', '').lower()
        ref = flow.request.headers.get('referer', '').lower()
        if 'python-requests' in ua or 'curl' in ua:
            ctx.log.warn(f"[Suspicious User-Agent] {ua} for {url}")
            self.report.setdefault('suspicious_user_agents', []).append((url, ua))
            if DASHBOARD_AVAILABLE:
                dashboard.add_log('WARNING', f"[Suspicious User-Agent] {ua} for {url}")
        if ref and not urlparse(url).netloc in ref:
            ctx.log.warn(f"[Suspicious Referrer] {ref} for {url}")
            self.report.setdefault('suspicious_referrers', []).append((url, ref))
            if DASHBOARD_AVAILABLE:
                dashboard.add_log('WARNING', f"[Suspicious Referrer] {ref} for {url}")
        # Suspicious parameter detection
        if any(q in url.lower() for q in ['cmd=', 'exec=', 'base64', 'powershell']):
            ctx.log.warn(f"[Suspicious Query Param] {url}")
            self.report.setdefault('suspicious_params', []).append(url)
            if DASHBOARD_AVAILABLE:
                dashboard.add_log('WARNING', f"[Suspicious Query Param] {url}")
        # Credential leak detection stub (TODO: parse POST bodies for sensitive fields)
        # TODO: Integrate threat intelligence feeds, whitelist/blacklist
        for keyword in PHISHING_KEYWORDS:
            if keyword in url.lower():
                ctx.log.warn(f"[Phishing URL Detected] {url}")
                self.report['phishing_urls'].append(url)
                if DASHBOARD_AVAILABLE:
                    dashboard.add_log('WARNING', f"[Phishing URL Detected] {url}")
                # BLOCK the request
                flow.response = http.Response.make(
                    403,  # HTTP status code
                    b"<html><body><h1>Access Blocked</h1><p>This site is flagged as phishing or untrusted.</p></body></html>",
                    {"Content-Type": "text/html"}
                )
                return  # Stop further processing

    def response(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.pretty_url
        # Suspicious JS in HTML
        if "text/html" in flow.response.headers.get("content-type", ""):
            html = flow.response.text
            for pattern in SUSPICIOUS_JS_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    ctx.log.warn(f"[Suspicious JS Detected] {url} matches {pattern}")
                    self.report['suspicious_js'].append(url)
                    if DASHBOARD_AVAILABLE:
                        dashboard.add_log('WARNING', f"[Suspicious JS Detected] {url} matches {pattern}")
        # Unexpected redirects
        if flow.response.status_code in REDIRECT_CODES:
            loc = flow.response.headers.get("location", "")
            if loc:
                parsed = urlparse(loc)
                if parsed.netloc and not parsed.netloc.endswith("yourdomain.com"):
                    ctx.log.warn(f"[Unexpected Redirect] {url} -> {loc}")
                    self.report['unexpected_redirects'].append((url, loc))
                    if DASHBOARD_AVAILABLE:
                        dashboard.add_log('WARNING', f"[Unexpected Redirect] {url} -> {loc}")
        # SSL/TLS fingerprint mismatch (mitmproxy handles SSL, so this is simulated)
        if flow.server_conn and hasattr(flow.server_conn, 'certificate_list'):
            # In real world, compare fingerprint to known-good. Here, just log as example.
            pass  # Placeholder for actual fingerprint check

def load(l):
    if not hasattr(ctx, 'report'):
        ctx.report = {'phishing_urls': [], 'suspicious_js': [], 'unexpected_redirects': [], 'malware_found': [], 'downloads_scanned': 0}
    l.addons.add(TrafficAnalyzer(ctx.report))
