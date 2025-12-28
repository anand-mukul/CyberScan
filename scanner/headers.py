import requests

class HeaderScanner:
    def __init__(self):
        self.required_headers = [
            "X-Frame-Options",           # Prevents Clickjacking
            "X-XSS-Protection",          # Old browser XSS filter
            "Content-Security-Policy",   # Controls resources the user agent is allowed to load
            "Strict-Transport-Security"  # Enforces HTTPS
        ]

    def scan(self, url):
        try:
            res = requests.get(url)
            missing_headers = []
            
            for header in self.required_headers:
                if header not in res.headers:
                    missing_headers.append(header)
            
            return {
                "url": url,
                "missing": missing_headers
            }
        except:
            return None