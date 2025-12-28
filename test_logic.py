from scanner.crawler import Crawler
from scanner.sqli import SQLInjector
from scanner.xss import XSSScanner
from scanner.headers import HeaderScanner

# TARGET: Use a safe, authorized educational site
# http://testphp.vulnweb.com is designed for this exact purpose.
target_url = "http://testphp.vulnweb.com/login.php" 

print(f"--- Starting Scan on {target_url} ---")

# 1. Crawl
crawler = Crawler(target_url)
forms = crawler.get_forms(target_url)
print(f"[+] Found {len(forms)} forms.")

# 2. Scan Headers
header_scanner = HeaderScanner()
header_res = header_scanner.scan(target_url)
print(f"[+] Missing Headers: {header_res['missing']}")

# 3. Active Scanning (SQLi & XSS)
# Note: We share the crawler's session so cookies persist
sqli_scanner = SQLInjector(crawler.session)
xss_scanner = XSSScanner(crawler.session)

for form in forms:
    details = crawler.extract_form_details(form)
    
    # Test SQLi
    sqli_vulns = sqli_scanner.scan_form(details)
    if sqli_vulns:
        print(f"[!!!] SQLi Found: {sqli_vulns}")
        
    # Test XSS
    xss_vulns = xss_scanner.scan_form(details)
    if xss_vulns:
        print(f"[!!!] XSS Found: {xss_vulns}")

print("--- Scan Complete ---")