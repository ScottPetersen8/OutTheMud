# TripWire

**Incident Detection & Log Analysis System**

TripWire is a Ruby-based forensic tool designed for rapid incident analysis on Windows servers. It collects, correlates, and analyzes logs from multiple sources to help you understand what happened during production incidents.

---

## 🎯 What It Does

- **Collects logs** from Windows Event Logs, Datadog, PostgreSQL, and file-based sources
- **Time-focused analysis** - analyze specific incident windows (last 2h, yesterday, etc.)
- **Extracts alerts** - automatically flags ERROR, FATAL, CRASH, PANIC keywords
- **Generates reports** - converts raw logs into human-readable format
- **Captures snapshots** - saves system state (disk, memory) at collection time

---

## 📋 Requirements

- **Ruby 3.x** (tested on Ruby 3.4)
- **Windows OS** (for Windows Event Log collection)
- **PowerShell** (for event log queries)
- **Administrator privileges** (for Security event log access)

---

## 🚀 Quick Start

### Basic Usage

# Analyze last 24 hours (default)
ruby bin/tripwire.rb

# Analyze last 2 hours
ruby bin/tripwire.rb --last 2h

# Analyze yesterday
ruby bin/tripwire.rb --yesterday

# Analyze today
ruby bin/tripwire.rb --today

# Custom time range
ruby bin/tripwire.rb --last 6h
ruby bin/tripwire.rb --back 2d      # 2 days ago
ruby bin/tripwire.rb --back 1w3d    # 1 week, 3 days ago


### Common Scenarios

# Production outage investigation (verbose output)
ruby bin/tripwire.rb --last 2h --verbose

# Skip Windows logs (faster, for file logs only)
ruby bin/tripwire.rb --last 4h --skip-windows

# Skip system snapshot
ruby bin/tripwire.rb --yesterday --skip-snapshot

# Collect all Security events (not just critical ones)
ruby bin/tripwire.rb --last 1h --all-security


---

## 📁 Output Structure

TripWire creates a timestamped folder with all collected data:


TripWire_20260115-104259/
├── SUMMARY.txt                    # High-level summary
├── summary.log                    # Detailed log
├── Windows/
│   ├── System/
│   │   └── System.tsv            # Windows System events
│   ├── Application/
│   │   └── Application.tsv       # Application events
│   └── Security/
│       └── Security.tsv          # Security events
├── Datadog/
│   └── Datadog.tsv               # Datadog logs
├── PostgreSQL/
│   └── PostgreSQL.tsv            # PostgreSQL logs
├── Alerts/
│   ├── alerts_System.tsv         # Extracted alerts
│   ├── alerts_Application.tsv
│   └── alerts_Security.tsv
├── Reports/
│   ├── system.txt                # Human-readable reports
│   ├── application.txt
│   ├── security.txt
│   ├── alerts_system.txt
│   └── datadog.txt
└── Snapshot/
    ├── disk.tsv                  # Disk usage snapshot
    └── mem.tsv                   # Memory snapshot

---

## ⚙️ Configuration

### Via `config/config.yml`

# Log file paths (auto-detected if not specified)
paths:
  datadog: 'C:/ProgramData/Datadog/logs'
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log'

# Default options
options:
  verbose: false
  skip_windows: false
  skip_snapshot: false
  parallel: false

### Via Command Line


# Override log paths
ruby bin/tripwire.rb --datadog "D:/Datadog/logs" --postgres "D:/PostgreSQL/logs"

# Processing options
ruby bin/tripwire.rb --verbose           # Detailed logging
ruby bin/tripwire.rb --parallel          # Parallel Windows log collection
ruby bin/tripwire.rb --skip-windows      # Skip Windows Event Logs
ruby bin/tripwire.rb --skip-snapshot     # Skip system snapshot
ruby bin/tripwire.rb --all-security      # Collect ALL Security events
ruby bin/tripwire.rb --all-levels        # Collect all log levels (not just errors)

---

## 🔍 How It Works

### 1. Path Resolution

TripWire automatically searches for log directories:

1. Uses configured paths from `config.yml`
2. Tries common default locations
3. Searches likely directories (C:\, D:\, ProgramData, etc.)
4. Falls back to empty TSV if not found

**Supported Products:**
- Datadog (`C:/ProgramData/Datadog/logs`)
- PostgreSQL (`C:/Program Files/PostgreSQL/*/data/log`)

### 2. Log Collection

**Windows Event Logs:**
- Uses PowerShell `Get-WinEvent` with time filters
- Collects System, Application, and Security logs
- Converts to TSV format for easy parsing

**File-Based Logs:**
- Scans directories recursively
- Filters by file modification time
- Parses timestamps from log lines
- Extracts severity (ERROR, WARN, INFO)

### 3. Alert Extraction

Scans all collected logs for keywords:
- `shutdown`, `crash`, `panic`, `fail`
- `error`, `critical`, `fatal`, `exception`

Creates separate alert TSVs in the `Alerts/` folder.

### 4. Report Generation

Converts TSV files to human-readable text reports with:
- Timestamp formatting
- Severity indicators
- Source attribution
- Message cleaning (removes tabs, newlines)

---

## 🛠️ Troubleshooting

### "PowerShell timeout" Error

**Cause:** Security log has too many events (takes >60 seconds)

**Fix:** Increase timeout in `lib/config.rb`:

PS_TIMEOUT = 300  # 5 minutes instead of 60 seconds


### "Access Denied" to Security Log

**Cause:** Requires administrator privileges

**Fix:** Run Command Prompt as Administrator

### "Path not found" Warnings

**Cause:** TripWire can't auto-detect log directories

**Fix:** Specify paths explicitly:

ruby bin/tripwire.rb --datadog "D:/logs/datadog" --postgres "E:/PostgreSQL/logs"


Or configure in `config/config.yml`:

paths:
  datadog: 'D:/logs/datadog'
  postgresql: 'E:/PostgreSQL/logs'


### Empty TSV Files

**Cause:** No logs found in the time window

**Fix:** 
- Expand time range: `--last 24h` instead of `--last 1h`
- Check log paths are correct
- Verify logs exist for that time period

### IOError in PowerShell

**Cause:** Large log queries timing out or failing

**Fix:**
- Increase `PS_TIMEOUT` in config
- Use `--last 2h` instead of `--last 24h` to reduce data
- Limit Security events with default filters (don't use `--all-security`)

---

## 📊 Understanding the Output

### SUMMARY.txt

═══════════════════════════════════════════════════════════════
TripWire v3.2 - Summary
═══════════════════════════════════════════════════════════════
Duration: 326.77s
Range: 2026-01-15 09:48 → 2026-01-15 10:48
Files: 3 | Lines: 394647 | Errors: 0 | Alerts: 7
Output: C:/users/scottp/documents/outthemud/tripwire/TripWire_20260115-104259
═══════════════════════════════════════════════════════════════


- **Duration:** How long collection took
- **Range:** Time window analyzed
- **Files:** Number of log files processed
- **Lines:** Total log lines collected
- **Errors:** File read/processing errors
- **Alerts:** Keywords matched

### TSV Files

Tab-separated values for programmatic processing:

**Windows Events:**

TimeCreated             Id    LevelDisplayName  ProviderName        Message
2026-01-15 09:42:15    1000  Information       Service Control...  Service started


**File Logs:**

timestamp               severity  message                          source
2026-01-15 09:42:30    ERROR     Connection timeout after 30s     app.log


### Report Files

Human-readable text with cleaned formatting:

================================================================================
TripWire Report: security.txt
================================================================================

[2026-01-15 09:42:15] INFO     | Security             | User login successful [4624]
[2026-01-15 09:43:22] WARNING  | Security             | Failed login attempt [4625]


---

## 🔧 Advanced Usage

### Parallel Collection (Faster)

ruby bin/tripwire.rb --last 4h --parallel

Collects Windows logs (System, Application, Security) in parallel threads.

### Custom Time Parsing

# Last N hours/days/weeks/months
--last 6h     # Last 6 hours
--last 2d     # Last 2 days
--last 1w     # Last 1 week
--last 1m     # Last 1 month

# Specific past periods
--back 2d     # All of 2 days ago
--back 1w3d   # 1 week and 3 days ago
--back 2m1w   # 2 months and 1 week ago


### Debugging


# Enable debug logging
ruby bin/tripwire.rb --last 1h --verbose

# Shows:
# - PowerShell scripts being executed
# - Path resolution steps
# - File processing details
# - Timestamp parsing
```

---

## 🏗️ Architecture

### Core Modules

- **`TripWire::Runner`** - Main orchestrator
- **`TripWire::Logger`** - Singleton logging system
- **`TripWire::Stats`** - Event counters
- **`TripWire::TimeParser`** - Time range parsing
- **`TripWire::PathResolver`** - Auto-detect log directories
- **`TripWire::PowerShell`** - Execute PowerShell scripts
- **`TripWire::TSV`** - TSV file I/O

### Collectors

- **`Collectors::Windows`** - Windows Event Logs via PowerShell
- **`Collectors::Files`** - File-based logs (Datadog, PostgreSQL, etc.)

### Processors

- **`Processors::Alerts`** - Keyword-based alert extraction
- **`Processors::Reports`** - TSV → readable text conversion
- **`Processors::Snapshot`** - System state capture

---

## 📝 Command Reference

```
Usage: ruby tripwire.rb [options]

Time Options:
  --last D              Duration (6h, 2d, 1w, 1m)
  --back D              Offset from now (2m1w3d)
  --today               Analyze today (midnight to now)
  --yesterday           Analyze yesterday (full day)

Path Options:
  --datadog PATH        Override Datadog log path
  --postgres PATH       Override PostgreSQL log path

Processing Options:
  --verbose             Enable debug logging
  --parallel            Parallel Windows log collection
  --skip-windows        Skip Windows Event Logs
  --skip-snapshot       Skip system snapshot
  --all-security        Collect ALL Security events (not just critical)
  --all-levels          Collect all log levels (not just errors/warnings)

Info:
  -h, --help           Show help
  --version            Show version
```

---

## 🐛 Known Issues

1. **Large Security logs timeout** - Use `--last 2h` or increase `PS_TIMEOUT`
2. **Requires admin for Security log** - Run as Administrator
3. **Path auto-detection can be slow** - Configure paths explicitly in config.yml
4. **Unicode characters in logs** - Handled via UTF-8 encoding with replacement

---

## 📄 License

Internal tool - proprietary

---

## 🤝 Contributing

This is an internal incident response tool. For improvements or bug reports, contact the development team.

---

## 📞 Support

For issues during incident response:
1. Check verbose output: `--verbose`
2. Verify admin privileges
3. Check log paths are accessible
4. Review `summary.log` in output folder

**Emergency fallback:** Manually collect logs from known paths if TripWire fails.

---
  
**Last Updated:** January 2026  
**Maintained By:** Internal DevOps Team