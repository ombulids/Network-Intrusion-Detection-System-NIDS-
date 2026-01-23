# 🛡️ Sentinel-Sec: Integrated NIDS & Web Vulnerability Scanner

A dual-purpose Cybersecurity toolkit designed for 2nd-year AI/ML students to monitor network traffic and audit web application security.

## 🚀 Overview
This project combines two core security pillars into one interface:
1. **Network Intrusion Detection (NIDS):** Real-time packet sniffing and threat detection using Scapy.
2. **Web Vulnerability Scanner:** An active scanner that identifies SQL Injection (SQLi) and Cross-Site Scripting (XSS) vulnerabilities in web forms.

## ✨ Features
### 1. Network IDS
- **Live Sniffing:** Captures TCP/IP packets across local interfaces.
- **Threat Detection:** Flags suspicious patterns like SYN floods and unauthorized port scans.
- **Logging:** Automatically logs suspicious IP addresses for later review.

### 2. Web Vulnerability Scanner
- **Form Discovery:** Automatically crawls a target URL to find all HTML input forms.
- **Payload Injection:** Tests fields with industry-standard SQLi and XSS payloads.
- **Detection Logic:** Analyzes HTTP responses for database error signatures and script reflections.

## 🛠️ Tech Stack
- **Language:** Python 3.x
- **Libraries:** - `Scapy` (Network Analysis)
  - `Requests` (HTTP Communication)
  - `BeautifulSoup4` (HTML Parsing)
  - `Streamlit` (Web Interface)

## 📦 Installation & Usage
1. **Clone the Repo:**
   ```bash
   git clone [https://github.com/yourusername/sentinel-sec.git](https://github.com/yourusername/sentinel-sec.git)
   cd sentinel-sec