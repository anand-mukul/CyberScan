# CyberScan
## Automated Vulnerability Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask-green?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red?style=for-the-badge)](https://owasp.org/)

**CyberScan** is an advanced, automated web vulnerability scanner designed for educational and defensive security purposes. It systematically crawls web applications to detect critical security flaws such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Sensitive Data Exposure, providing a comprehensive audit report with remediation strategies.

---

## 🚀 Features

### 🔍 Intelligence & Detection
* **Active Scanning Engine:** Detects **SQL Injection** (Error-based) and **Reflected XSS** via safe payload injection.
* **Network Reconnaissance:** Scans common TCP ports (21, 22, 80, 443, 3306) to identify exposed services.
* **Sensitive Path Discovery:** hunts for accidental leaks like `.env`, `backup.sql`, `.git`, and `config.php`.
* **Security Header Analysis:** Checks for missing defensive headers (CSP, HSTS, X-Frame-Options).

### 📊 Visualization & Reporting
* **Cyberpunk Dashboard:** A professional, glassmorphic UI with real-time scanning feedback.
* **Risk Scoring System:** Algorithms calculate a precise **Security Grade (A-F)** and **Risk Score (0-10)** based on findings.
* **Professional PDF Reports:** Generates detailed, branded audit reports compliant with penetration testing standards.
* **Auto-Remediation:** Provides developer-friendly code snippets (Python/PHP) to fix every discovered vulnerability.

---

## 🛠️ Technology Stack

* **Core:** Python 3.x
* **Web Framework:** Flask (Jinja2)
* **Engine:** `Requests`, `BeautifulSoup4` (Crawling & Injection)
* **Reporting:** `ReportLab` (PDF Generation)
* **Frontend:** HTML5, CSS3, Bootstrap 5, Chart.js

---

## ⚙️ Installation & Setup

### Prerequisites
* Python 3.8 or higher installed.
* Git installed.

### 1. Clone the Repository
```bash
git clone https://github.com/anand-mukul/CyberScan.git
cd CyberScan

```

### 2. Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate

```

### 3. Install Dependencies

```bash
pip install -r requirements.txt

```

*(If `requirements.txt` is missing, install manually: `pip install flask requests beautifulsoup4 reportlab`)*

### 4. Run the Application

```bash
python app.py

```

### 5. Access the Dashboard

Open your browser and navigate to:
`http://127.0.0.1:5000`

---

## 🧪 How to Test (Demo Targets)

For educational testing, use these authorized vulnerable applications:

1. **Acunetix VulnWeb (PHP):** `http://testphp.vulnweb.com`
* *Expected Result:* Grade F (SQLi, XSS found).


2. **Google (Baseline):** `https://www.google.com`
* *Expected Result:* Grade A (Secure).


3. **Altoro Mutual Bank:** `http://demo.testfire.net`
* *Expected Result:* Grade F (High Risk).



> **⚠️ Ethical Disclaimer:** This tool is for **educational and defensive use only**. Scanning targets without explicit written consent is illegal. The developer assumes no liability for misuse.

---

## 📸 Screenshots

| **Dashboard** | **Scan Results** |
| --- | --- |
|![Home Screen Dashboard](https://github.com/anand-mukul/CyberScan/blob/main/public/dashboard.png)|![Scan Result - Vulnerable Target](https://github.com/anand-mukul/CyberScan/blob/main/public/scanResult.png)|

---

## 🔮 Future Scope

* **Authenticated Scanning:** Support for Login/Session-based crawling.
* **AI Integration:** Machine Learning to reduce false positives in WAF detection.
* **API Security:** Specialized scanning for REST/GraphQL endpoints.

---

## 🤝 Contribution

Contributions are welcome! Please fork the repo and create a pull request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

Distributed under the [MIT License](https://choosealicense.com/licenses/mit/). See `LICENSE` for more information.

---

### Author

**Mukul Anand**
*Cybersecurity Researcher & Developer*
[LinkedIn Profile](https://www.linkedin.com/in/dev-mukul) | [GitHub Profile](https://github.com/anand-mukul)
