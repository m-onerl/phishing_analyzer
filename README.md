# 📧 Phishing Email Analyzer

**Application for Detecting Phishing Attacks in Email Messages**

##  Project Overview

Phishing Email Analyzer is a Python desktop application designed to automatically scan email inboxes for suspicious or malicious links. The application connects to a user's mailbox via the IMAP protocol, extracts hyperlinks from email content, and checks them using the VirusTotal API. If any threats are detected, emails are moved to a dedicated "Phishing" folder.

##  Technologies Used

* **Python 3.8+**
* **IMAPClient / imaplib** – email server communication
* **BeautifulSoup (bs4)** – for parsing HTML content
* **Requests** – HTTP communication with VirusTotal API
* **Tkinter** – GUI interface
* **email, json, urllib, base64, re, threading** – built-in and external modules

##  Features

* IMAP login and mail server configuration (Gmail, WP, Onet, Interia, etc.)
* Automatic scanning of inbox messages (supports HTML and plain text)
* URL extraction and filtration
* Integration with VirusTotal API for real-time threat analysis
* Filtering out tokenized/one-time links (e.g., auth, token, verify)
* Automatic tagging and moving of phishing emails
* Multithreaded background execution
* Intuitive graphical interface (GUI) built with Tkinter

---

##  Getting Started

###  Prerequisites

* Python 3.8 or newer
* Internet access
* Email account with IMAP enabled
* Free VirusTotal API key ([virustotal.com](https://www.virustotal.com/))

###  Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/YourUsername/phishing-email-analyzer.git
   cd phishing-email-analyzer
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Add your API key in the configuration file:

   ```
   config/token
   api-key=YOUR_API_KEY_HERE
   ```

4. Run the application:

   ```bash
   python main.py
   ```

##  Testing

This application includes both unit and integration tests:

* `test_imap_client.py` – IMAP message fetching
* `test_link_analyzer.py` – VirusTotal integration and URL checks
* `test_email_analyzer.py` – mail message parsing logic
* `test_functional.py` – functional email-to-threat detection flow
* `test_integration.py` – end-to-end email scanning tests

To run tests:

```bash
pytest
```

##  Two-Factor Authentication Support

If your email provider uses 2FA (e.g., Gmail), use an **App Password** generated in your account settings instead of your regular password.

##  Project Structure

```
├── imap_client.py        # Handles IMAP login and mail processing
├── email_analyzer.py     # Coordinates scanning and logic control
├── link_analyzer.py      # Interfaces with VirusTotal API
├── gui.py                # Tkinter-based user interface
├── main.py               # Entry point for launching application
├── config/token          # Stores your VirusTotal API key
```

##  Deployment Requirements

* OS: Windows 10+, macOS, or any modern Linux
* CPU: Dual-core (Intel i3 8th gen or equivalent recommended)
* RAM: 4 GB minimum, 8 GB recommended
* Disk: 100 MB available space
* Python: Version 3.8 or later
* Internet: Required for IMAP and API functionality

##  Performance Insights

* RAM Usage: \~90–120 MB during scanning of 20 emails
* CPU Usage: Peaks at \~40% on modern i5 processors during initial scans

##  Architecture Summary

The application is modularized into three layers:

* **UI Layer** – for user input and output via Tkinter
* **Logic Layer** – for processing and managing mail and links
* **Network Layer** – for IMAP and VirusTotal API communication

##  Key Modules

* **IMAPClient**: Connects to the email server, fetches messages, moves phishing to folders
* **LinkAnalyzer**: Checks link reputation with VirusTotal
* **EmailAnalyzer**: Integrates above modules to perform email scanning
* **GUI**: Provides user-friendly interface for configuration and control

##  Known Issues & Solutions

*  **API limits**: Caching and throttling used to avoid VirusTotal rate limits
*  **Regex errors**: Solved using BeautifulSoup for accurate HTML parsing
*  **Thread cleanup**: Fixed by using daemon threads to prevent resource leakage

##  Author

Sebastian Wołoszyn
Faculty of Information and Communication Technology
Wrocław University of Science and Technology
