# Log Analyzer 🛡️

A Python-based **Log Analyzer** for cybersecurity purposes.  
This project parses, classifies, and analyzes system, authentication, and web logs, assigning risk levels to suspicious activities. Ideal for learning practical log analysis, Python scripting, and building security monitoring pipelines.

---

## 🚀 Features

- **Universal Log Parsing:** Handles authentication logs, web server logs, and system events.
- **Event Classification:** Detects events such as:
  - Failed login attempts
  - Invalid user access
  - HTTP requests (with status codes)
  - System errors
- **Risk Assessment:** Assigns risk levels (`LOW`, `MEDIUM`, `HIGH`) based on event severity.
- **IP Monitoring:** Tracks IP activity and ranks suspicious IPs based on cumulative risk.
- **JSON Output:** Stores processed logs in NDJSON format for easy integration with other tools.
- **Modular Design:** Python classes for parsing (`Parser`), detecting (`Detection`), and reporting (`Analyzer`).

---

## 📂 Project Structure

log-analyzer/<br/>
├── logs/ # Sample log files<br/>
│ └── auth_sample.log<br/>
├── output/ # Output directory (stores analysis results)<br/>
│ └── .gitkeep<br/>
├── src/ # Source code<br/>
│ ├── analyzer.py<br/>
│ ├── detector.py<br/>
│ ├── parser.py<br/>
│ ├── pipeline.py<br/>
│ └── report.py<br/>
├── main.py # Entry point for running the analyzer<br/>
├── requirements.txt # Python dependencies<br/>
└── README.md<br/>

---

## 🛠️ Installation

1. Clone the repository:

`bash<br/>
git clone https://github.com/NatnaelEndale/log-analyzer.git
cd log-analyzer`

2. Create a virtual environment (recommended):

python -m venv venv<br/>
source venv/bin/activate       # Linux / Mac<br/>
venv\Scripts\activate          # Windows<br/>

Install dependencies:<br/>
`pip install -r requirements.txt`

## ⚡ Usage

Run the analyzer on your log files:

`python main.py --log-file logs/auth_sample.log`

Output will be stored in `output/log_analysis_report.json`

Example Output (NDJSON)
{"ip": "192.168.1.1", "event_type": "FAILED_LOGIN", "subtype": "INVALID_USER", "risk": "HIGH"}<br/>
{"ip": "192.168.1.2", "event_type": "HTTP_REQUEST", "endpoint": "/admin", "status_code": "403", "risk": "MEDIUM"}<br/>
{"ip": "127.0.0.1", "event_type": "SYSTEM_ERROR", "message": "Failed to start service", "risk": "HIGH"}<br/>
## 💡 How It Works

Parsing: Reads log files and extracts relevant fields (IP, status, login event, system message, web request).<br/>
Detection: Classifies each event into predefined types and calculates risk.<br/>
Analysis: Aggregates events by IP and ranks suspicious activity.<br/>
Reporting: Outputs a structured JSON report for further analysis.<br/>

## 🏗️ Future Improvements

Support for more log formats (CSV, JSON, Apache/Nginx logs).<br/>
CLI interface with filters and options for interactive use.<br/>
Integration with alerting systems (email, Slack, etc.).<br/>
Visualization dashboards for easier monitoring.<br/>

## 📚 Learning Outcomes
Python OOP: modular design and class-based structure.<br/>
Regex mastery for parsing logs efficiently.<br/>
Risk-based event classification logic.<br/>
NDJSON formatting and JSON handling.<br/>
Basic cybersecurity awareness via log monitoring.<br/>

## 👨‍💻 Author

Natnael Endale – GitHub Profile

## 📄 License

This project is open-source and licensed under the MIT License.




