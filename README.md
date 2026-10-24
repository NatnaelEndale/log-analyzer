# Log Analyzer

A modular Python command-line tool for parsing, classifying, and summarizing
authentication, web-server, and system logs.

The project is designed as a practical learning project for Python
development, regular expressions, object-oriented design, command-line
interfaces, and basic security monitoring concepts.

## Features

- Parses common authentication, HTTP, and `systemd` log entries.
- Extracts timestamps, IP addresses, login events, HTTP requests, status codes,
  and system messages.
- Classifies events, including:
  - Successful logins
  - Failed logins
  - Invalid-user login attempts
  - HTTP requests
  - System logs
  - System errors
- Assigns `LOW`, `MEDIUM`, or `HIGH` risk levels.
- Identifies suspicious activity involving protected endpoints such as
  `/admin`.
- Writes analyzed events as newline-delimited JSON (NDJSON).
- Generates summaries of event types, risk levels, suspicious IP addresses, and
  frequently accessed endpoints.
- Creates missing output directories automatically.
- Provides separate `analyze` and `report` CLI commands.

## How it works

The application processes logs in four stages:

1. **Parsing** - [`Parser`](src/parser.py) reads each non-empty line and
   extracts fields using regular expressions.
2. **Detection** - [`Detection`](src/detector.py) classifies each parsed record
   and assigns a risk level.
3. **Pipeline** - [`Pipeline`](src/pipeline.py) coordinates parsing and
   detection, then writes the results to an NDJSON file.
4. **Reporting** - [`Analyzer`](src/analyzer.py) aggregates activity by IP,
   while [`Report`](src/report.py) prints summaries and alerts.

## Project structure

```text
log-analyzer/
├── logs/
│   └── auth_sample.log       # Sample input log
├── results/                  # Generated reports
├── src/
│   ├── __init__.py
│   ├── analyzer.py           # IP aggregation and ranking
│   ├── detector.py           # Event classification and risk assessment
│   ├── parser.py             # Log parsing
│   ├── pipeline.py           # Parse, detect, and write workflow
│   └── report.py             # Human-readable summaries and alerts
├── main.py                   # Command-line entry point
├── requirements.txt          # Project dependencies
└── README.md
```

## Requirements

- Python 3.9 or later

The current implementation uses Python's standard library and does not require
third-party packages.

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/NatnaelEndale/log-analyzer.git
cd log-analyzer
```

Creating a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\activate
```

If project dependencies are added later, install them with:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

### Analyze a log file

Run the analyzer using the sample log:

```bash
python3 main.py analyze logs/auth_sample.log
```

The default output is written to:

```text
results/report.json
```

Although the file extension is `.json`, the output is NDJSON: each line is a
separate JSON object. A custom output path can be provided:

```bash
python3 main.py analyze logs/auth_sample.log \
    --output results/custom-report.json
```

The parent directory is created automatically when it does not exist.

### Generate a report

Generate a human-readable report from the default analysis file:

```bash
python3 main.py report
```

To report on a different analysis file:

```bash
python3 main.py report \
    --input results/custom-report.json
```

The report includes:

- Alerts for high-risk activity
- Total events
- Authentication, web, and system event counts
- Successful and failed login counts
- System error counts
- Low-, medium-, and high-risk event counts
- Suspicious IP addresses and their event reasons
- Endpoint access frequencies

Use the command-line help to see the available commands and options:

```bash
python3 main.py --help
python3 main.py analyze --help
python3 main.py report --help
```

## Output format

The analyzer writes one JSON object per line. For example:

```json
{"ip": "192.168.1.1", "event_type": "FAILED_LOGIN", "risk": "HIGH", "time_stamp": "Mar 18 10:22:01"}
{"ip": "192.168.1.1", "event_type": "HTTP_REQUEST", "status_code": "401", "endpoint": "/admin", "risk": "MEDIUM", "time_stamp": "Mar 18 11:00:01"}
{"ip": null, "event_type": "SYSTEM_ERROR", "risk": "HIGH", "message": "Failed to start MySQL Database Service.", "time_stamp": "Mar 18 12:15:42"}
```

The exact fields depend on the information available in each input log line.

## Current detection rules

The current detector uses the following rules:

| Event | Detection | Risk |
| --- | --- | --- |
| `FAILED_LOGIN` | The log contains `Failed password` | `HIGH` |
| `FAILED_LOGIN` with `INVALID_USER` subtype | The log contains `invalid user` | `HIGH` |
| `SUCCESS_LOGIN` | The log contains `Accepted password` | `LOW` |
| `HTTP_REQUEST` | A quoted request contains `HTTP` | Usually `LOW` |
| Protected HTTP request | Status `401` or `403` and endpoint contains `/admin` | `MEDIUM` |
| `SYSTEM_ERROR` | A system message contains `Failed to start` | `HIGH` |
| `SYSTEM_LOG` | Other recognized `systemd` messages | `LOW` |

These rules are intentionally simple and are intended for learning and
extension rather than production security monitoring.

## Sample workflow

```bash
# 1. Analyze the source log
python3 main.py analyze logs/auth_sample.log \
    --output results/report.json

# 2. Review the generated report
python3 main.py report \
    --input results/report.json
```

## Limitations

This project currently targets the sample log formats included in the
repository. Real-world logs vary considerably, so the parser may not recognize
every valid format. In particular:

- Log formats are detected using regular expressions rather than dedicated
  format parsers.
- The risk rules are heuristic and should not be treated as a complete
  intrusion-detection system.
- The output is NDJSON rather than a single JSON array.
- There is currently no database, dashboard, alerting integration, or real-time
  log monitoring.
- Automated test coverage is still a future improvement.

## Future improvements

Possible extensions include:

- Add automated unit and integration tests.
- Improve support for Apache, Nginx, SSH, and other log formats.
- Validate IP addresses and timestamps more strictly.
- Add configurable detection and risk rules.
- Add CSV and standard JSON export options.
- Return structured report data separately from console formatting.
- Add logging and user-friendly CLI error messages.
- Support filtering by date, IP, event type, or risk level.
- Add real-time monitoring and integrations with alerting services.
- Add a dashboard for visualizing trends and suspicious activity.

## Learning goals

This project provides practice with:

- Python modules and classes
- Regular expressions
- `pathlib` and file I/O
- `argparse` subcommands
- JSON and NDJSON serialization
- Data aggregation
- Basic security-event classification
- Designing a small multi-module application

## License

This project is open source and licensed under the MIT License.
