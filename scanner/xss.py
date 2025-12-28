import requests

class XSSScanner:
    def __init__(self, session):
        self.session = session
        # A harmless JavaScript payload
        self.payload = "<script>alert('XSS')</script>"

    def scan_form(self, form_details):
        target_url = form_details["action"]
        vulnerabilities = []

        # Create the data dictionary with our payload
        data = {}
        for input_tag in form_details["inputs"]:
            if input_tag["type"] != "submit":
                data[input_tag["name"]] = self.payload
        
        # Send Request
        if form_details["method"] == "post":
            res = self.session.post(target_url, data=data)
        else:
            res = self.session.get(target_url, params=data)
            
        # Analyze: If our script tag comes back in the HTML, it's vulnerable
        if self.payload in res.content.decode():
            print(f"[!] XSS detected on {target_url}")
            vulnerabilities.append({
                "url": target_url,
                "type": "Reflected XSS",
                "payload": self.payload,
                "details": "Payload reflected in response HTML."
            })
            
        return vulnerabilities