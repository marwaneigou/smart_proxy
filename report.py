from mitmproxy import ctx

def done():
    report = getattr(ctx, 'report', None)
    if not report:
        print("No report found.")
        return
    print("\n===== SESSION SUMMARY =====")
    print(f"Phishing URLs detected: {len(report['phishing_urls'])}")
    print(f"Suspicious JS detected: {len(report['suspicious_js'])}")
    print(f"Unexpected redirects: {len(report['unexpected_redirects'])}")
    print(f"Downloads scanned: {report['downloads_scanned']}")
    print(f"Malware found: {len(report['malware_found'])}")
    if report['malware_found']:
        for url, reason in report['malware_found']:
            print(f"  - {url} ({reason})")
    print("==========================\n")
