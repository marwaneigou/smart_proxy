from traffic_analyzer import TrafficAnalyzer
from malware_scanner import MalwareScanner
from mitmproxy import ctx
import report

class CombinedAddon:
    def __init__(self):
        self.report = {'phishing_urls': [], 'suspicious_js': [], 'unexpected_redirects': [], 'malware_found': [], 'downloads_scanned': 0}
        self.analyzer = TrafficAnalyzer(self.report)
        self.scanner = MalwareScanner(self.report)

    def request(self, flow):
        self.analyzer.request(flow)

    def response(self, flow):
        self.analyzer.response(flow)
        self.scanner.response(flow)

    def done(self):
        report.done()

addons = [CombinedAddon()]
