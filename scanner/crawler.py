import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        # Fake a browser user-agent so we aren't blocked immediately
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Educational Vulnerability Scanner)'
        })

    def get_forms(self, url):
        """Extracts all forms from a webpage."""
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException as e:
            print(f"[-] Connection Error: {e}")
            return []

    def extract_form_details(self, form):
        """
        Extracts useful info from a form: action URL, method (GET/POST), and inputs.
        This data is crucial for the SQLi and XSS modules.
        """
        details = {}
        
        # Get the form action (target URL)
        action = form.attrs.get("action")
        if action:
            # Handle relative URLs (e.g., /login.php -> http://site.com/login.php)
            action = urljoin(self.target_url, action)
        else:
            action = self.target_url
            
        method = form.attrs.get("method", "get").lower()
        
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type, 
                "name": input_name,
                "value": input_value
            })
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

# --- Test Snippet (Run this file directly to test) ---
if __name__ == "__main__":
    target = "http://testphp.vulnweb.com/login.php" # Safe educational test site
    spider = Crawler(target)
    forms = spider.get_forms(target)
    print(f"[+] Found {len(forms)} forms on {target}")
    
    for i, form in enumerate(forms):
        details = spider.extract_form_details(form)
        print(f"\nForm #{i+1} Details:")
        print(details)