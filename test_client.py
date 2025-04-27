import requests
import time
from urllib.parse import urlparse

# Configuration
PROXY = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}
CA_CERT = 'C:/Users/igou/.mitmproxy/mitmproxy-ca-cert.pem'  # Update this path
SLEEP_DELAY = 1  # Seconds between tests

class SecurityTester:
    def __init__(self, proxy, verify_cert=None):
        self.proxy = proxy
        self.verify = verify_cert
        self.results = {
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

    def _make_request(self, url, allow_redirects=False, method='GET'):
        try:
            if method == 'GET':
                response = requests.get(
                    url,
                    proxies=self.proxy,
                    verify=self.verify,
                    allow_redirects=allow_redirects,
                    timeout=10
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    proxies=self.proxy,
                    verify=self.verify,
                    allow_redirects=allow_redirects,
                    timeout=10
                )
            
            domain = urlparse(url).netloc
            return {
                'url': url,
                'domain': domain,
                'status': response.status_code,
                'headers': dict(response.headers),
                'redirects': response.history,
                'success': True
            }
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'success': False
            }

    def test_phishing(self):
        """Test known phishing patterns"""
        print("\n=== Testing Phishing URLs ===")
        test_urls = [
            'http://fake-login-page.com/login.php',  # Simulated
            'https://phishtank.org/developer_info.php',  # Phishtank test
            'http://malware.testing.google.test/testing/malware/',
            'http://evilsite.com/steal-creds'  # Simulated
        ]
        
        for url in test_urls:
            result = self._make_request(url)
            self._log_result('Phishing', url, result)
            time.sleep(SLEEP_DELAY)

    def test_malicious_js(self):
        """Test sites with suspicious JavaScript behavior"""
        print("\n=== Testing Malicious JavaScript ===")
        test_urls = [
            'http://www.xss-payloads.com',
            'https://cryptojacking-test.net',  # Simulated
            'http://malicious-iframe.example.com',  # Simulated
            'https://malware.testing.google.test/testing/malware/'
        ]
        
        for url in test_urls:
            result = self._make_request(url)
            self._log_result('Malicious JS', url, result)
            time.sleep(SLEEP_DELAY)

    def test_redirects(self):
        """Test malicious redirect patterns"""
        print("\n=== Testing Suspicious Redirects ===")
        test_urls = [
            'http://httpbin.org/redirect-to?url=http://evil.com',
            'https://google.com/goto/http://malicious.site',  # Will fail
            'http://redirect-test.com/300',  # Multiple redirects
            'http://legitsite.com/out?url=http://phishing.com'  # Simulated
        ]
        
        for url in test_urls:
            result = self._make_request(url, allow_redirects=False)
            self._log_result('Redirect', url, result)
            time.sleep(SLEEP_DELAY)

    def test_downloads(self):
        """Test suspicious file downloads"""
        print("\n=== Testing File Downloads ===")
        test_urls = [
            'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
            'http://speedtest.ftp.otenet.gr/files/test100k.db',
            'http://malware.testing.google.test/testing/malware/',  # Will fail
            'http://evil.com/setup.exe'  # Simulated
        ]
        
        for url in test_urls:
            result = self._make_request(url)
            self._log_result('Download', url, result)
            time.sleep(SLEEP_DELAY)

    def test_ssl(self):
        """Test SSL/TLS vulnerabilities"""
        print("\n=== Testing SSL/TLS Issues ===")
        test_urls = [
            'https://expired.badssl.com',
            'https://self-signed.badssl.com',
            'https://untrusted-root.badssl.com',
            'https://sha1-intermediate.badssl.com'
        ]
        
        for url in test_urls:
            result = self._make_request(url)
            self._log_result('SSL', url, result)
            time.sleep(SLEEP_DELAY)

    def _log_result(self, test_type, url, result):
        """Log and categorize test results"""
        if result.get('success', False):
            print(f"[✓] {test_type}: {url} - Status {result['status']}")
            self.results['passed'] += 1
            
            # Check for suspicious headers
            if 'X-XSS-Protection' not in result.get('headers', {}):
                print(f"    Warning: Missing XSS protection header")
                self.results['warnings'] += 1
                
        else:
            print(f"[✗] {test_type}: {url} - Error: {result.get('error', 'Unknown')}")
            self.results['failed'] += 1

    def run_all_tests(self):
        """Execute all test categories"""
        print(f"Starting security tests via proxy {self.proxy['http']}")
        
        self.test_phishing()
        self.test_malicious_js()
        self.test_redirects()
        self.test_downloads()
        self.test_ssl()
        
        print("\n=== Test Summary ===")
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")
        print(f"Warnings: {self.results['warnings']}")
        
        return self.results

if __name__ == '__main__':
    tester = SecurityTester(proxy=PROXY, verify_cert=CA_CERT)
    tester.run_all_tests()