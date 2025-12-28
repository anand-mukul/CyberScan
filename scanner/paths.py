import requests

class PathScanner:
    def __init__(self, session):
        self.session = session
        self.sensitive_paths = [
            ".env",
            "config.php",
            ".git/HEAD",
            "backup.zip",
            "db_backup.sql",
            "phpinfo.php",
            "admin/",
            "dashboard/"
        ]

    def scan(self, base_url):
        findings = []
        if not base_url.endswith("/"):
            base_url += "/"

        for path in self.sensitive_paths:
            target = base_url + path
            try:
                res = self.session.get(target, timeout=3, allow_redirects=False)
                
                # SMART FILTER:
                # 1. Ignore redirects (301/302)
                # 2. Ignore login pages masquerading as 200 OK
                if res.status_code == 200:
                    content = res.text.lower()
                    is_valid = True

                    # False Positive Check 1: If we asked for a binary file (.zip) but got HTML
                    if path.endswith(".zip") and "html" in content:
                        is_valid = False
                    
                    # False Positive Check 2: If we asked for .env but got HTML or no "=" signs
                    if path == ".env" and ("<html" in content or "=" not in content):
                        is_valid = False

                    # False Positive Check 3: Common "Not Found" text hiding in 200 OK
                    if "page not found" in content or "login" in content:
                        is_valid = False

                    if is_valid:
                        findings.append({
                            "type": "Sensitive Path Disclosed",
                            "url": target,
                            "payload": f"GET {path}",
                            "desc": f"Direct access allowed to '{path}'. Potential information leak.",
                            "fix_title": "Restrict Access",
                            "fix_code": "Configure your server (Apache/Nginx) to block access to hidden files starting with dot (.)",
                            "severity": "Medium" if "admin" in path else "High"
                        })
            except:
                pass
        
        return findings