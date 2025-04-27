# Proxy Traffic Analyzer & Malware Scanner

## Features
- Intercepts HTTP/HTTPS traffic using mitmproxy
- Detects suspicious URLs, headers, redirects, JS, and SSL issues
- Scans downloads for malware using ClamAV (pyclamd) or static patterns
- Logs and summarizes suspicious/malicious activity

## Setup
1. Install Python 3.x
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. (Optional, for malware scanning) Install ClamAV and run clamd service.

## Running the Proxy
```
mitmdump -s main.py
```
- By default, mitmproxy listens on 127.0.0.1:8080
- Configure your browser/system to use this as HTTP/HTTPS proxy

## Testing
Run the provided `test_client.py` to simulate browsing and downloads.

## Notes
- For HTTPS interception, install mitmproxy's certificate in your browser/system.
- On Windows, you may need to run mitmdump as Administrator for SSL/TLS interception.
