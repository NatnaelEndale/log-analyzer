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
log-analyzer/
├── logs/ # Sample log files
│ └── auth_sample.log
├── output/ # Output directory (stores analysis results)
│ └── .gitkeep
├── src/ # Source code
│ ├── analyzer.py
│ ├── detector.py
│ ├── parser.py
│ ├── pipeline.py
│ └── report.py
├── main.py # Entry point for running the analyzer
├── requirements.txt # Python dependencies
└── README.md

---

## 🛠️ Installation

1. Clone the repository:

bash 
git clone https://github.com/NatnaelEndale/log-analyzer.git
cd log-analyzer

2. Create a virtual environment (recommended):
python -m venv venv
source venv/bin/activate       # Linux / Mac
venv\Scripts\activate          # Windows

Install dependencies:
pip install -r requirements.txt

⚡ Usage

Run the analyzer on your log files:

python main.py --log-file logs/auth_sample.log

Output will be stored in output/log_analysis_report.json

Example Output (NDJSON)
{"ip": "192.168.1.1", "event_type": "FAILED_LOGIN", "subtype": "INVALID_USER", "risk": "HIGH"}
{"ip": "192.168.1.2", "event_type": "HTTP_REQUEST", "endpoint": "/admin", "status_code": "403", "risk": "MEDIUM"}
{"ip": "127.0.0.1", "event_type": "SYSTEM_ERROR", "message": "Failed to start service", "risk": "HIGH"}
💡 How It Works
Parsing: Reads log files and extracts relevant fields (IP, status, login event, system message, web request).
Detection: Classifies each event into predefined types and calculates risk.
Analysis: Aggregates events by IP and ranks suspicious activity.
Reporting: Outputs a structured JSON report for further analysis.
🏗️ Future Improvements
Support for more log formats (CSV, JSON, Apache/Nginx logs).
CLI interface with filters and options for interactive use.
Integration with alerting systems (email, Slack, etc.).
Visualization dashboards for easier monitoring.
📚 Learning Outcomes
Python OOP: modular design and class-based structure.
Regex mastery for parsing logs efficiently.
Risk-based event classification logic.
NDJSON formatting and JSON handling.
Basic cybersecurity awareness via log monitoring.
👨‍💻 Author

Natnael Endale – GitHub Profile

📄 License

This project is open-source and licensed under the MIT License.




