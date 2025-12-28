from flask import Flask, render_template, request, send_file, session, redirect, url_for
from scanner.crawler import Crawler
from scanner.sqli import SQLInjector
from scanner.xss import XSSScanner
from scanner.headers import HeaderScanner
from scanner.report import PDFReporter
from scanner.ports import PortScanner
from scanner.paths import PathScanner 
import socket
import datetime
import os
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# --- INTELLIGENCE DATABASE ---
KNOWLEDGE_BASE = {
    "SQL Injection": {
        "owasp": "A03:2021-Injection",
        "score": 9.0,
        "severity": "Critical",
        "desc": "Untrusted data is sent to an interpreter as part of a command or query.",
        "fix_title": "Use Parameterized Queries",
        "fix_code": r"""# VULNERABLE:
cursor.execute("SELECT * FROM users WHERE user = '" + username + "'")

# SECURE (Python):
cursor.execute("SELECT * FROM users WHERE user = %s", (username,))"""
    },
    "Reflected XSS": {
        "owasp": "A03:2021-Injection",
        "score": 7.5,
        "severity": "High",
        "desc": "The application includes untrusted data in a new web page without proper validation.",
        "fix_title": "Context-Aware Encoding",
        "fix_code": r"""<div>Welcome, <?php echo $_GET['user']; ?></div>

<div>Welcome, <?php echo htmlspecialchars($_GET['user']); ?></div>"""
    },
    "Sensitive Path Disclosed": {
        "owasp": "A05:2021-Security Misconfiguration",
        "score": 6.5,
        "severity": "Medium",
        "desc": "Sensitive files (config, backups) are accessible to the public.",
        "fix_title": "Restrict Access",
        "fix_code": r"""# Apache (.htaccess):
<FilesMatch "\.(env|sql|git)">
    Order allow,deny
    Deny from all
</FilesMatch>"""
    },
    "Missing Headers": {
        "owasp": "A05:2021-Security Misconfiguration",
        "score": 4.0,
        "severity": "Low",
        "desc": "Important security headers (CSP, HSTS) are missing.",
        "fix_title": "Server Configuration",
        "fix_code": r"""# Nginx Config:
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";"""
    }
}

PORT_INFO = {
    21: {"service": "FTP", "risk": "High", "fix": "Use SFTP (Port 22)."},
    22: {"service": "SSH", "risk": "Medium", "fix": "Disable root login."},
    80: {"service": "HTTP", "risk": "Low", "fix": "Redirect to HTTPS."},
    443: {"service": "HTTPS", "risk": "Safe", "fix": "Ensure TLS 1.2+."},
    3306: {"service": "MySQL", "risk": "Critical", "fix": "Block external access."}
}

def get_ip_address(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        return socket.gethostbyname(hostname)
    except:
        return None

def normalize_url(url):
    """Auto-adds http:// if missing"""
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def calculate_risk_score(vulns, headers, ports):
    current_score = 10.0
    
    for v in vulns:
        kb = KNOWLEDGE_BASE.get(v['type'], {})
        deduction = kb.get('score', 5.0) * 0.5 
        current_score -= deduction

    if headers.get('missing'):
        current_score -= 1.0

    for p in ports:
        if PORT_INFO.get(p, {}).get("risk") in ["High", "Critical"]:
            current_score -= 1.5

    final_score = max(0, round(current_score, 1))
    
    if final_score >= 9.0: grade, color = "A", "success"
    elif final_score >= 7.5: grade, color = "B", "info"
    elif final_score >= 5.0: grade, color = "C", "warning"
    elif final_score >= 2.5: grade, color = "D", "danger"
    else: grade, color = "F", "danger" 
    
    return final_score, grade, color

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url')
    if not raw_url: return render_template('index.html', error="Enter URL")
    
    target_url = normalize_url(raw_url)
    
    ip = get_ip_address(target_url)
    if not ip: return render_template('index.html', error="Could not resolve host. Check URL.")

    # Init Modules
    crawler = Crawler(target_url)
    sqli = SQLInjector(crawler.session)
    xss = XSSScanner(crawler.session)
    headers = HeaderScanner()
    ports = PortScanner()
    paths = PathScanner(crawler.session)

    # Scans
    forms = crawler.get_forms(target_url) or []
    header_res = headers.scan(target_url) or {"missing": []}
    open_ports = ports.scan(ip)
    path_vulns = paths.scan(target_url)

    vuln_results = []
    
    for form in forms:
        details = crawler.extract_form_details(form)
        for v in sqli.scan_form(details):
            v.update(KNOWLEDGE_BASE["SQL Injection"])
            vuln_results.append(v)
        for v in xss.scan_form(details):
            v.update(KNOWLEDGE_BASE["Reflected XSS"])
            vuln_results.append(v)

    for v in path_vulns:
        v.update(KNOWLEDGE_BASE["Sensitive Path Disclosed"])
        vuln_results.append(v)

    risk_score, grade, grade_color = calculate_risk_score(vuln_results, header_res, open_ports)
    
    port_analysis = []
    for p in open_ports:
        info = PORT_INFO.get(p, {"service": "Unknown", "risk": "Unknown", "fix": "Check manually"})
        port_analysis.append({**info, "port": p})

    report = {
        "target": target_url,
        "ip": ip,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "grade": grade,
        "grade_color": grade_color,
        "risk_score": risk_score,
        "vuln_count": len(vuln_results),
        "forms_found": len(forms),
        "vulnerabilities": vuln_results,
        "headers": header_res,
        "ports": port_analysis,
        "open_ports": open_ports
    }

    pdf = PDFReporter()
    filename = pdf.generate(report)
    session['report_file'] = filename

    return render_template('results.html', report=report)

@app.route('/download')
def download_pdf():
    filename = session.get('report_file')
    if not filename:
        return redirect(url_for('home'))
        
    path = os.path.join("static/reports", filename)
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)