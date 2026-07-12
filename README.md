# Keylogger Detector

**Real-time anti-keylogger tool that monitors system keyboard hooks, scans running processes for malicious signatures, and blocks unauthorized keystroke capture to safeguard user privacy.**

---

## 🛡️ Overview

Keylogger Detector is a defensive security tool designed to protect your system from keylogger threats. It continuously monitors running processes, system hooks, persistence mechanisms, and network connections to detect suspicious keylogger-like activity. The tool provides a real-time GUI dashboard for easy visualization and reporting capabilities.

**Important**: This tool is strictly defensive and designed for system protection only. It never captures keystrokes and operates transparently on your system.

---

## 📸 GUI Interface

The Keylogger Detector features an intuitive CustomTkinter-based GUI dashboard that provides real-time monitoring and threat detection:

![Keylogger Sentinel GUI Dashboard](https://raw.githubusercontent.com/user-attachments/image-1.png)

**GUI Features:**
- **Start Scan Button** - Initiates real-time process scanning and threat analysis
- **Auto Refresh** - Continuously monitors system for new threats
- **Export** - Save findings in JSON, CSV, or HTML format
- **Whitelist** - Manage and suppress false positives
- **Live Statistics** - Real-time threat count display (Processes, Scanned, Critical, High, Medium, Low)
- **Process Table** - Detailed view with PID, Name, Severity, Score, CPU%, Memory, and SHA-256 hashes
- **Detail Sidebar** - In-depth information about selected findings
- **Color-Coded Severity** - Visual indicators for threat levels (Critical, High, Medium, Low)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **🔍 Process Scanner** | Enumerates all running processes and flags suspicious keywords, paths, and execution patterns |
| **🔐 Persistence Scanner** | Detects persistence mechanisms in Registry, Startup folders, Task Scheduler, systemd, crontab, and LaunchAgents |
| **🌐 Network Monitor** | Monitors outbound connections and flags suspicious ports and long-lived external connections |
| **🔎 File Reputation** | Performs SHA-256 hash lookups against configurable known-bad hash lists |
| **📊 Risk Scoring Engine** | Weighted scoring system with configurable thresholds and severity levels |
| **📈 Live GUI Dashboard** | Real-time CustomTkinter interface with process table, detail sidebar, and color-coded severity indicators |
| **📋 Multi-Format Reporting** | Export findings to JSON, CSV, and styled HTML reports |
| **🔄 Auto-Refresh** | Configurable periodic re-scanning with customizable intervals |
| **🔔 Desktop Notifications** | Instant alerts for critical and high-severity threats |
| **✅ Whitelist Management** | Suppress false positives by whitelisting known-good processes |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/R4nkW0rld/keyloggerdetector.git
cd keyloggerdetector

# Install dependencies
pip install -r requirements.txt
```

### Launch GUI

```bash
python main.py
```

### CLI Mode

```bash
python main.py --cli
```

### Custom Configuration

```bash
python main.py --config /path/to/config.yaml
```

---

## 🏗️ Architecture

```
keylogger_sentinel/
├── main.py                    # Entry point (GUI + CLI)
├── config.yaml                # Tunable configuration
├── known_bad_hashes.yaml      # Known-bad SHA-256 hashes
├── requirements.txt
├── core/
│   ├── models.py              # Dataclasses: Finding, ScanResult, Severity, etc.
│   ├── scanner.py             # Process enumeration and analysis
│   ├── persistence.py         # Persistence mechanism detection
│   ├── network.py             # Network connection monitoring
│   ├── reputation.py          # SHA-256 hash reputation checking
│   ├── scoring.py             # Weighted risk scoring engine
│   └── detector.py            # Orchestrator tying all modules together
├── gui/
│   ├── app.py                 # Main application window
│   ├── tables.py              # Finding table widget
│   ├── widgets.py             # Status bar, summary cards, detail sidebar
│   └── dialogs.py             # Confirm, whitelist, export dialogs
├── reporting/
│   ├── json_report.py         # JSON export
│   ├── csv_report.py          # CSV export
│   └── html_report.py         # Styled HTML export
├── utils/
│   ├── config.py              # YAML config loader with deep merge
│   ├── logger.py              # Rotating file logger
│   └── whitelist.py           # Whitelist manager
└── samples/
    ├── sample_report.json
    ├── sample_report.csv
    └── sample_report.html
```

---

## 🔬 Detection Logic

### Process Risk Signals

| Signal | Weight | Description |
|--------|--------|-------------|
| **Keyword Match** | +15 each | Process name/cmdline contains: `keylog`, `hook`, `capture`, `clipboard`, `spy`, `autohotkey` |
| **Suspicious Path** | +20 each | Executable in `/tmp`, `Downloads`, `AppData/Local/Temp`, `/dev/shm` |
| **Suspicious Parent** | +10 | Process spawned by suspicious parent (e.g., `powershell.exe` from `wscript.exe`) |
| **Hidden Execution** | +15 each | Null-byte prefix, dotfile on Linux, stealth flags (`--hidden`, `--daemon`) |
| **System Hooks** | +35 each | Command line references hook APIs: `SetWindowsHookEx`, `GetAsyncKeyState`, `evdev`, `xdotool` |
| **Known-Bad Hash** | +40 | SHA-256 matches entry in `known_bad_hashes.yaml` |
| **Network Connection** | +25 each | Outbound connection to suspicious port (4444, 1337, etc.) or long-lived external TCP |
| **Persistence Mechanism** | +20 each | Registry autorun, systemd service, crontab entry, LaunchAgent, `.desktop` autostart |

### Severity Classification

| Level | Score Range | Description |
|-------|------------|-------------|
| **Low** 🟡 | 0–25 | Minor signals, likely false positive |
| **Medium** 🟠 | 26–50 | Multiple signals, worth investigating |
| **High** 🔴 | 51–75 | Strong indicators of suspicious activity |
| **Critical** ⛔ | 76+ | Multiple strong indicators, immediate action required |

---

## ⚙️ Configuration

Edit `config.yaml` to customize the scanner behavior:

```yaml
weights:
  keyword_match: 15
  suspicious_path: 20
  suspicious_parent: 10
  hidden_execution: 15
  system_hooks: 35
  known_bad_hash: 40
  network_connection: 25
  persistence: 20

thresholds:
  low: 0
  medium: 26
  high: 51
  critical: 76

scan_interval_seconds: 10

whitelist:
  names:
    - "svchost.exe"
    - "explorer.exe"
  pids: []
  paths: []

known_bad_hashes_file: "known_bad_hashes.yaml"
```

### Tuning False Positives

1. **Add to Whitelist**: Right-click a finding in the GUI → "Whitelist" to exclude by PID or name
2. **Edit Configuration**: Modify `config.yaml` and add legitimate process names to `whitelist.names`
3. **Adjust Weights**: Lower point values for detection categories producing noise
4. **Raise Thresholds**: Increase `thresholds.high` and `thresholds.critical` if getting too many alerts

---

## 📊 Reporting

Export scan results to multiple formats in the `reports/` directory:

- **JSON**: Machine-readable format with complete breakdown and timestamps
- **CSV**: Spreadsheet-compatible format with one row per finding
- **HTML**: Styled, color-coded report with detailed threat analysis

---

## 🔧 Extending the Tool

### Add Custom Detection Logic

1. Add keyword patterns to `ProcessScanner.KEYWORD_PATTERNS`
2. Add persistence paths to `PersistenceScanner` class attributes
3. Add suspicious ports to `NetworkMonitor.SUSPICIOUS_PORTS`
4. Override `RiskScoringEngine.score()` with custom signal handlers

### Add Known-Bad Hashes

Update `known_bad_hashes.yaml` with SHA-256 hashes from threat intelligence sources:

```yaml
hashes:
  - sha256: "abc123def456..."
    description: "Malware family X variant"
  - sha256: "789ghi012jkl..."
    description: "Known keylogger hash"
```

---

## 🛡️ Safety & Privacy

- ✅ **Read-Only Operations**: Never modifies processes, registry, or files
- ✅ **No Keystroke Capture**: Only analyzes process metadata and system state
- ✅ **Local Processing**: All data remains on your local machine
- ✅ **Transparent**: Runs visibly in process list using standard system APIs
- ✅ **User-Controlled**: No auto-start behavior; user must explicitly launch
- ✅ **False Positive Management**: Comprehensive whitelist support for known-good processes

---

## 📋 Requirements

- Python 3.8+
- Windows, macOS, or Linux
- Administrator/root privileges for full system scanning

---

## 📝 License

MIT License - Use responsibly for defensive security purposes only.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

---

## ⚖️ Disclaimer

This tool is designed for defensive security monitoring on your own systems only. Unauthorized access to computer systems is illegal. Always use this tool responsibly and with proper authorization.

---

**Made with ❤️ for system security**
