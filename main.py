import yaml
import json
import threading
import time
from traffic_analyzer import TrafficAnalyzer
from malware_scanner import MalwareScanner
from mitmproxy import ctx
import report
import os

# Import dashboard module
try:
    import dashboard
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False
    print("Dashboard module not available. Install Flask and Flask-SocketIO.")

# Load config.yaml
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(CONFIG_PATH, 'r') as f:
    config = yaml.safe_load(f)

# Load or create whitelist.json
WHITELIST_PATH = os.path.join(os.path.dirname(__file__), 'whitelist.json')
def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            print(f"Error loading whitelist: {e}")
    return set(['google.com', 'microsoft.com', 'apple.com'])  # Default trusted domains

def save_whitelist(whitelist):
    try:
        with open(WHITELIST_PATH, 'w') as f:
            json.dump(list(whitelist), f, indent=2)
    except Exception as e:
        print(f"Error saving whitelist: {e}")

# Global report data shared between mitmproxy and dashboard
shared_report = {'phishing_urls': [], 'suspicious_js': [], 'unexpected_redirects': [], 
                 'malware_found': [], 'downloads_scanned': 0, 'suspicious_user_agents': [],
                 'suspicious_referrers': [], 'suspicious_params': []}

class CombinedAddon:
    def __init__(self):
        self.report = shared_report
        self.analyzer = TrafficAnalyzer(self.report, config)
        self.scanner = MalwareScanner(self.report, config)
        self.config = config
        
        # Load whitelist domains
        if not hasattr(ctx, 'whitelist'):
            ctx.whitelist = load_whitelist()
            print(f"Loaded {len(ctx.whitelist)} domains in whitelist.")
        
        # Start dashboard if enabled
        if DASHBOARD_AVAILABLE and config.get('dashboard', {}).get('enabled', False):
            self.start_dashboard()

    def start_dashboard(self):
        """Start the dashboard in a separate thread"""
        dashboard_thread = threading.Thread(target=dashboard.run_dashboard)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        # Start a thread to periodically save the report
        if self.config.get('report', {}).get('persist_session', False):
            save_thread = threading.Thread(target=self.periodic_save_report)
            save_thread.daemon = True
            save_thread.start()
            
        print(f"Dashboard started at http://{config['dashboard']['host']}:{config['dashboard']['port']}")
        print(f"Username: {config['dashboard']['username']}, Password: {config['dashboard']['password']}")
        
    def periodic_save_report(self):
        """Periodically save the report to file for dashboard to read"""
        while True:
            # Save report to file
            fname = self.config['report'].get('report_file', 'session_report.json')
            with open(fname, 'w') as f:
                json.dump(self.report, f, indent=2)
            # Wait before next save
            time.sleep(self.config['dashboard'].get('refresh_interval', 5))

    def request(self, flow):
        self.analyzer.request(flow)
        # Log to dashboard if available
        if DASHBOARD_AVAILABLE:
            dashboard.add_log('INFO', f"Request: {flow.request.method} {flow.request.pretty_url}")

    def response(self, flow):
        self.analyzer.response(flow)
        self.scanner.response(flow)
        # Log to dashboard if available
        if DASHBOARD_AVAILABLE:
            dashboard.add_log('INFO', f"Response: {flow.response.status_code} {flow.request.pretty_url}")

    def done(self):
        report.done()
        # Session persistence: save report to file if enabled
        if self.config.get('report', {}).get('persist_session', False):
            fname = self.config['report'].get('report_file', 'session_report.json')
            with open(fname, 'w') as f:
                json.dump(self.report, f, indent=2)
            if DASHBOARD_AVAILABLE:
                dashboard.add_log('INFO', f"Session report saved to {fname}")

addons = [CombinedAddon()]
