# Keylogger Sentinel

**Defensive keylogger detection tool for your own machine.**

Keylogger Sentinel scans running processes, persistence mechanisms, network connections, and file hashes to detect suspicious keylogger-like activity. It is **strictly defensive** — it never captures keystrokes, records input, or sends data off-machine.

## Features

| Feature | Description |
|---------|-------------|
| **Process Scanner** | Enumerates processes via psutil; flags suspicious keywords, paths, parents, hidden execution |
| **Persistence Scanner** | Checks Windows Registry, Startup folders, Task Scheduler, systemd, crontab, LaunchAgents |
| **Network Monitor** | Monitors outbound connections; flags suspicious ports and long-lived external connections |
| **File Reputation** | SHA-256 hash lookup against a configurable known-bad hash list |
| **Risk Scoring** | Weighted scoring with configurable thresholds and severity levels |
| **GUI Dashboard** | CustomTkinter live dashboard with process table, detail sidebar, color-coded severity |
| **Reporting** | Export to JSON, CSV, and styled HTML |
| **Auto-refresh** | Configurable periodic re-scan |
| **Desktop Notifications** | Alerts for critical/high severity findings |
| **Whitelist** | Suppress false positives by whitelisting known-good processes |

## Quick Start

### Install

```bash
# Clone or download the project
cd keylogger_sentinel

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

### Custom Config

```bash
python main.py --config /path/to/config.yaml
```

## Architecture

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

## Detection Logic

### Process Signals

| Signal | Weight | Description |
|--------|--------|-------------|
| **Keyword Match** | +15 each | Process name/cmdline contains terms like `keylog`, `hook`, `capture`, `clipboard`, `spy`, `autohotkey` |
| **Suspicious Path** | +20 each | Executable in `/tmp`, `Downloads`, `AppData/Local/Temp`, `/dev/shm` |
| **Suspicious Parent** | +10 | E.g. `powershell.exe` spawned by `wscript.exe` or `outlook.exe` |
| **Hidden Execution** | +15 each | Null-byte prefix, dotfile on Linux, stealth flags (`--hidden`, `--daemon`) |
| **System Hooks** | +35 each | Command line references hook APIs: `SetWindowsHookEx`, `GetAsyncKeyState`, `evdev`, `xdotool` |
| **Known-Bad Hash** | +40 | SHA-256 matches an entry in `known_bad_hashes.yaml` |
| **Network Connection** | +25 each | Outbound connection to suspicious port (4444, 1337, etc.) or established external TCP |
| **Persistence** | +20 each | Registry autorun, systemd service, crontab entry, LaunchAgent, autostart `.desktop` |

### Severity Levels

| Level | Score Range | Description |
|-------|------------|-------------|
| **Low** | 0–25 | Minor signals, likely false positive |
| **Medium** | 26–50 | Multiple signals, worth investigating |
| **High** | 51–75 | Strong indicators of suspicious activity |
| **Critical** | 76+ | Multiple strong indicators, immediate attention |

### Tuning False Positives

1. **Add to whitelist**: Right-click a finding → "Whitelist" to exclude by PID or name
2. **Edit `config.yaml`**: Add legitimate process names to `whitelist.names`
3. **Reduce weights**: Lower scores for categories that produce noise in your environment
4. **Adjust thresholds**: Raise `thresholds.high` if you get too many high-severity alerts

## Configuration

Edit `config.yaml` to tune the scanner:

- `weights`: Adjust point values for each detection category
- `thresholds`: Change score breakpoints for severity levels
- `whitelist`: Add known-good process names, PIDs, or paths
- `scan_interval_seconds`: Auto-refresh interval
- `known_bad_hashes_file`: Path to your hash database

## Reporting

Reports are exported to the `reports/` directory:

- **JSON**: Machine-readable, includes full breakdown with timestamps
- **CSV**: Spreadsheet-compatible, one row per finding
- **HTML**: Styled report with color-coded severity and detail sections

## Extending

### Add Custom Detection Logic

1. Add new keyword patterns to `ProcessScanner.KEYWORD_PATTERNS`
2. Add new persistence paths to `PersistenceScanner` class attributes
3. Add suspicious ports to `NetworkMonitor.SUSPICIOUS_PORTS`
4. Override `RiskScoringEngine.score()` with custom signal handlers

### Add Hash Feeds

Update `known_bad_hashes.yaml` with SHA-256 hashes from your threat intel sources:

```yaml
hashes:
  - sha256: "your_hash_here"
    description: "Source description"
```

## Safety

- **Read-only**: Never modifies processes, registry, or files
- **No keystroke capture**: Only checks process metadata, never reads input
- **No network exfiltration**: All data stays on the local machine
- **No stealth**: Runs visibly in process list, uses standard system APIs
- **No auto-start**: User must explicitly launch the tool
- **Whitelist support**: Easily suppress false positives

## License

MIT License - Use responsibly for defensive security only.
