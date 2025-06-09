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

PHISHING_KEYWORDS = ["login", "secure", "account", "verify", "signin", "signup", "register", "authentication", "password", "credentials", "Verification"]
SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"setTimeout\s*\(\s*['\"]?[A-Za-z0-9+/=]{8,}['\"]?\)",
    r"(document\.execCommand\(['\"]copy['\"]\)|navigator\.clipboard\.writeText|clipboardData\.setData)",  # Clipboard manipulation
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
        ctx.log.info(f"Analyzing response from URL: {url}")
        # Suspicious JS in HTML
        if "text/html" in flow.response.headers.get("content-type", ""):
            html = flow.response.text
            for pattern in SUSPICIOUS_JS_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    ctx.log.warn(f"[Suspicious JS Detected] {url} matches {pattern}")
                    self.report['suspicious_js'].append(url)
                    if DASHBOARD_AVAILABLE:
                        dashboard.add_log('WARNING', f"[Suspicious JS Detected] {url} matches {pattern}")
                        
                    # Store the original response
                    original_response = flow.response.copy()
                    
                    # Generate a unique bypass token for this URL
                    import hashlib
                    import time
                    bypass_token = hashlib.md5(f"{url}:{time.time()}".encode()).hexdigest()[:10]
                    
                    # Create a session parameter to bypass this warning
                    bypass_param = f"bypass_js_warning={bypass_token}"
                    bypass_url = url
                    if "?" in url:
                        bypass_url = f"{url}&{bypass_param}"
                    else:
                        bypass_url = f"{url}?{bypass_param}"
                    
                    # Check if this request has the bypass parameter
                    request_url = flow.request.pretty_url
                    if "bypass_js_warning=" in request_url:
                        # Extract the token from the request URL
                        import urllib.parse
                        query = urllib.parse.urlparse(request_url).query
                        params = dict(urllib.parse.parse_qsl(query))
                        if "bypass_js_warning" in params:
                            # User clicked 'Continue Anyway', let the request pass through
                            ctx.log.info(f"[Suspicious JS] User bypassed warning for {url}")
                            if DASHBOARD_AVAILABLE:
                                dashboard.add_log('INFO', f"[Suspicious JS] User bypassed warning for {url}")
                            return
                    
                    # Create a warning page with a 'Continue Anyway' button
                    warning_html = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Security Alert - Suspicious JavaScript Detected</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f8f8; }}
                            .container {{ max-width: 800px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 5px; 
                                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                            h1 {{ color: #f39c12; margin-top: 0; }}
                            .info {{ border-left: 4px solid #f39c12; padding-left: 15px; margin: 20px 0; }}
                            .details {{ background-color: #f5f5f5; padding: 15px; border-radius: 4px; overflow-wrap: break-word; }}
                            .buttons {{ margin-top: 20px; }}
                            .btn {{ display: inline-block; padding: 10px 20px; margin-right: 10px; border-radius: 4px; 
                                    text-decoration: none; font-weight: bold; cursor: pointer; }}
                            .btn-danger {{ background-color: #e74c3c; color: white; border: none; }}
                            .btn-warning {{ background-color: #f39c12; color: white; border: none; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>⚠️ Security Alert: Suspicious JavaScript Detected</h1>
                            <p>Smart Proxy has detected potentially malicious JavaScript code on the page you are trying to access.</p>
                            
                            <div class="info">
                                <p><strong>URL:</strong> {url}</p>
                                <p><strong>Detection reason:</strong> Suspicious pattern: {pattern}</p>
                            </div>
                            
                            <div class="details">
                                <p><strong>Technical details:</strong></p>
                                <p>The webpage contains JavaScript code patterns that are commonly used in malicious attacks, 
                                such as phishing, data theft, or malware distribution.</p>
                            </div>
                            
                            <div class="buttons">
                                <a href="javascript:history.back()" class="btn btn-danger">Go Back (Recommended)</a>
                                <a href="{bypass_url}" class="btn btn-warning">Continue Anyway (Not Recommended)</a>
                            </div>
                            
                            <p style="margin-top: 20px;">If you believe this is a false positive, please contact your system administrator.</p>
                        </div>
                    </body>
                    </html>
                    """
                    
                    # Replace the response with our warning
                    flow.response = http.Response.make(
                        403,  # HTTP status code
                        warning_html.encode('utf-8'),
                        {"Content-Type": "text/html; charset=UTF-8"}
                    )
                    return  # Stop further pattern checking
        # Check for login/register pages and inject a warning popup
        if "text/html" in flow.response.headers.get("content-type", ""):
            html = flow.response.text
            login_page = False
            
            # Check if this is a login or register page
            login_keywords = ['login', 'sign in', 'signin', 'log in', 'register', 'sign up', 'signup', 'create account', 'verification', 'verify', 'account', 'authenticate', 'authentication']
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                page_title = title_match.group(1).lower()
                ctx.log.info(f"Page title: {page_title}")
                if any(keyword in page_title for keyword in login_keywords):
                    ctx.log.info(f"Found login keyword in title: {page_title}")
                    login_page = True
                    
            # Check for forms with password inputs
            password_form1 = re.search(r'<form[^>]*>.*<input[^>]+type=["\']?password["\']?', html, re.IGNORECASE | re.DOTALL)
            password_form2 = re.search(r'<input[^>]+type=["\']?password["\']?', html, re.IGNORECASE)
            if password_form1 or password_form2:
                ctx.log.info(f"Found password input field in form")
                login_page = True
            
            # Check for login/register related buttons or form actions
            button_match = re.search(r'<(button|input)[^>]*(value|name|id|class)=["\']?(login|signin|register|signup|verify|account|submit)', html, re.IGNORECASE)
            action_match = re.search(r'<form[^>]*action=["\']?[^>]*(phishing|malicious)', html, re.IGNORECASE)
            if button_match:
                ctx.log.info(f"Found login/register related button: {button_match.group(0)}")
                login_page = True
            if action_match:
                ctx.log.info(f"Found suspicious form action: {action_match.group(0)}")
                login_page = True
                
            # If login page detected, inject the warning popup
            if login_page:
                ctx.log.warn(f"[Possible Phishing Page Detected] {url}")
                ctx.log.info(f"Phishing indicators detected, injecting warning popup")
                # Make sure URL is added to the phishing_urls list
                if 'phishing_urls' not in self.report:
                    self.report['phishing_urls'] = []
                if url not in self.report['phishing_urls']:
                    self.report['phishing_urls'].append(url)
                if DASHBOARD_AVAILABLE:
                    dashboard.add_log('WARNING', f"[Possible Phishing Page Detected] {url}")
                
                # Create the warning popup
                phishing_popup = '''<script>
(function() {
    if (window.__phishingWarningInjected) return;
    window.__phishingWarningInjected = true;
    
    // Create popup element
    var popup = document.createElement('div');
    popup.id = "phishing-warning-popup";
    popup.style.position = "fixed";
    popup.style.top = "10px";
    popup.style.right = "10px";
    popup.style.maxWidth = "300px";
    popup.style.padding = "15px";
    popup.style.background = "#fff";
    popup.style.boxShadow = "0 2px 10px rgba(0,0,0,0.2)";
    popup.style.borderRadius = "5px";
    popup.style.zIndex = "99999";
    popup.style.border = "2px solid #e74c3c";
    
    // Add content
    popup.innerHTML = `
        <div style="text-align:center;">
            <h3 style="color:#e74c3c;margin:0 0 10px 0;font-size:16px;">⚠️ Verify This Website</h3>
            <p style="margin-bottom:12px;font-size:14px;">This appears to be a login page. Please verify it's legitimate before entering credentials.</p>
            <button onclick="document.getElementById('phishing-warning-popup').remove();" style="background:#e74c3c;color:#fff;padding:5px 10px;border:none;border-radius:3px;font-size:13px;cursor:pointer;">Dismiss Warning</button>
        </div>
    `;
    
    // Add to document
    document.body.appendChild(popup);
    
    // Auto-remove after 15 seconds
    setTimeout(function() {
        var popup = document.getElementById('phishing-warning-popup');
        if (popup) popup.remove();
    }, 15000);
})();
</script>''';
                
                # Try to inject before </body>, else append
                if "</body>" in html.lower():
                    html = re.sub(r"</body>", phishing_popup + "</body>", html, flags=re.IGNORECASE)
                else:
                    html += phishing_popup
                
                # Update the response with our modified HTML
                flow.response.text = html
        
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
                    
                    # Check if this is a redirect that the user has already chosen to bypass
                    if "bypass_redirect_warning=true" in url:
                        # Remove the bypass parameter and continue with the redirect
                        ctx.log.info(f"[Redirect Warning Bypassed] User continued to {loc}")
                        if DASHBOARD_AVAILABLE:
                            dashboard.add_log('INFO', f"[Redirect Warning Bypassed] User continued to {loc}")
                        return
                    
                    # Show a warning page about the redirect
                    redirect_warning_html = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Redirect Warning</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f8f8; }}
                            .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 5px; 
                                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                            h1 {{ color: #f39c12; margin-top: 0; }}
                            .info {{ border-left: 4px solid #f39c12; padding-left: 15px; margin: 20px 0; }}
                            .details {{ background-color: #f5f5f5; padding: 15px; border-radius: 4px; overflow-wrap: break-word; }}
                            .buttons {{ margin-top: 20px; }}
                            .btn {{ display: inline-block; padding: 10px 20px; margin-right: 10px; border-radius: 4px; 
                                  text-decoration: none; font-weight: bold; cursor: pointer; }}
                            .btn-back {{ background-color: #3498db; color: white; border: none; }}
                            .btn-continue {{ background-color: #f39c12; color: white; border: none; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>⚠️ Redirect Warning</h1>
                            <p>This page is trying to redirect you to another website. This could be legitimate but might also be a sign of a malicious redirect.</p>
                            
                            <div class="info">
                                <p><strong>Current page:</strong> {url}</p>
                                <p><strong>Redirecting to:</strong> {loc}</p>
                            </div>
                            
                            <div class="details">
                                <p>Unexpected redirects can sometimes lead to phishing sites or malicious content. Verify that you trust the destination before proceeding.</p>
                            </div>
                            
                            <div class="buttons">
                                <a href="javascript:history.back()" class="btn btn-back">Go Back (Recommended)</a>
                                <a href="{loc}?bypass_redirect_warning=true" class="btn btn-continue">Continue Anyway</a>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    
                    # Replace the redirect with our warning page
                    flow.response = http.Response.make(
                        200,  # HTTP status code
                        redirect_warning_html.encode(),
                        {"Content-Type": "text/html; charset=UTF-8"}
                    )
        # SSL/TLS fingerprint mismatch (mitmproxy handles SSL, so this is simulated)
        if flow.server_conn and hasattr(flow.server_conn, 'certificate_list'):
            # In real world, compare fingerprint to known-good. Here, just log as example.
            pass  # Placeholder for actual fingerprint check

def load(l):
    if not hasattr(ctx, 'report'):
        ctx.report = {'phishing_urls': [], 'suspicious_js': [], 'unexpected_redirects': [], 'malware_found': [], 'downloads_scanned': 0}
    l.addons.add(TrafficAnalyzer(ctx.report))
