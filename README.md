# Sentry Vulnerability Scanner

Sentry is a comprehensive web vulnerability scanner that helps developers and security engineers identify, analyze, and mitigate security flaws in modern web applications. The tool combines active and passive scanning techniques with AI-powered analysis to provide actionable insights.

## Architecture

```text
+-------------------+      +------------------+      +-------------------+
|                   |      |                  |      |                   |
|  Web Frontend     |      |  Flask Backend   |      |  Elasticsearch    |
|  (Port 8081)      |<---->|  (Port 5001)     |<---->|  (Data Store)     |
|                   |      |                  |      |                   |
+-------------------+      +------------------+      +-------------------+
        ^                           ^
        |                           |
+-------------------+      +------------------+
|                   |      |                  |
| Chrome Extension  |      |  Gemini AI       |
| (Manifest V3)     |      |  Integration     |
|                   |      |                  |
+-------------------+      +------------------+
```

## Key Features

- **Comprehensive Scanning:** Supports active (XSS, SQLi, etc.) and passive (header analysis, missing security flags) scanning.
- **Chrome Extension:** An intuitive browser extension for on-the-fly scanning and analysis.
- **AI-Powered Insights:** Uses Gemini AI for advanced vulnerability analysis and remediation recommendations.
- **OWASP Top 10 Coverage:** Prioritizes findings based on the OWASP Top 10 security risks.
- **Risk Scoring:** Intelligent scoring system (CVSS based) for accurate severity representation.

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Extension:** Manifest V3, JavaScript
- **Data Storage:** Elasticsearch
- **AI Integration:** Google Gemini AI

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/halalhacker/sentry-vuln-scanner.git
   cd sentry-vuln-scanner
   ```

2. **Set up the backend:**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure Elasticsearch:**
   - Install Elasticsearch locally or via Docker.
   - Update `backend/config.py` with your Elasticsearch credentials.

4. **Environment Variables:**
   Create a `.env` file in the root directory (based on `.env.example` if available) and add your `GEMINI_API_KEY`.

5. **Run the application:**
   - Backend: `python backend/app.py` (Runs on port 5001)
   - Frontend: Serve the `frontend/` directory (e.g., using `python -m http.server 8081`)

## Usage

1. Open the frontend in your browser (`http://localhost:8081`).
2. Add your target URLs and configure scan settings.
3. Initiate a scan and monitor the progress.
4. Review findings, AI insights, and remediation steps.
5. Alternatively, use the Chrome Extension by loading the `extension/` directory as an unpacked extension in Chrome.

## Screenshots

*(Screenshots coming soon)*

## License

This project is licensed under the MIT License.
