# TripWire v3.2

**Rapid Incident Response Log Aggregator & Analysis Tool**

TripWire is a Windows-based incident response tool that rapidly collects, aggregates, and analyzes logs from multiple sources (Windows Event Viewer, Datadog, PostgreSQL) to help you understand what happened during a critical incident. It's designed for speed and simplicity when you need answers fast.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Why TripWire?](#why-tripwire)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Usage Guide](#usage-guide)
- [Incident Response Scenarios](#incident-response-scenarios)
- [Configuration](#configuration)
- [Output](#output)
- [Troubleshooting](#troubleshooting)

---

## What It Does

TripWire automates the tedious process of collecting logs across multiple systems when you're investigating an incident:

1. **Collects Windows Event Logs**
   - System events (driver crashes, service failures, hardware issues)
   - Application events (app errors, warnings)
   - Security events (logins, logoffs, permission changes, account lockouts)

2. **Collects Application Logs**
   - Datadog agent logs (if installed)
   - PostgreSQL database logs
   - Custom application log files

3. **Filters by Time Range**
   - Only grabs logs from the period you care about
   - Saves time analyzing irrelevant old events

4. **Finds Issues Automatically**
   - Scans for error keywords (FATAL, EXCEPTION, TIMEOUT, etc.)
   - Extracts alerts into a separate report
   - Highlights critical patterns

5. **Generates Reports**
   - Organized file structure
   - Timeline of events
   - Summary statistics
   - Ready for analysis or sharing with team

---

## Why TripWire?

**The Problem:** When something goes wrong in production, you need to answer these questions *fast*:
- What error occurred?
- When did it happen?
- What else happened around that time?
- Who was accessing what?
- Did the database have issues?

Normally this means:
- ❌ Manually opening Event Viewer
- ❌ Searching multiple log files
- ❌ Copy-pasting data into Excel
- ❌ Correlating timestamps across systems
- ❌ Hours of manual work

**The Solution:** TripWire does this automatically in seconds.

---

## Quick Start

### Installation

1. Ensure you have Ruby installed: `ruby --version`
2. Download/clone TripWire
3. Edit `config/config.yml` with your log paths (if needed)
4. Run TripWire when an incident occurs

### Incident Response - Just Happened!

```powershell
# Run this to collect everything from the last 24 hours
ruby bin/tripwire.rb --last 1d

# Or if you know the exact time window:
ruby bin/tripwire.rb --start "2025-12-05 10:00:00" --end "2025-12-05 12:00:00"
```

That's it! Check the output folder for reports.

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       TripWire Core                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Windows    │  │   Datadog    │  │ PostgreSQL   │      │
│  │   Collector  │  │   Collector  │  │  Collector   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           │                                │
│                    ┌──────▼──────┐                         │
│                    │   Filters   │                         │
│                    │ - Time Range │                         │
│                    │ - Keywords   │                         │
│                    └──────┬──────┘                         │
│                           │                                │
│                  ┌────────▼────────┐                       │
│                  │  Alert Scanner  │                       │
│                  │ - Find errors   │                       │
│                  │ - Extract msgs  │                       │
│                  └────────┬────────┘                       │
│                           │                                │
│                  ┌────────▼────────┐                       │
│                  │ Report Generator│                       │
│                  │ - Timeline view │                       │
│                  │ - Statistics    │                       │
│                  │ - Summary       │                       │
│                  └────────┬────────┘                       │
│                           │                                │
│                    ┌──────▼──────┐                         │
│                    │Output Folder │                        │
│                    │- Events.tsv  │                        │
│                    │- Alerts.tsv  │                        │
│                    │- Reports/    │                        │
│                    │- SUMMARY.txt │                        │
│                    └──────────────┘                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Module Structure

```
lib/
├── cli.rb                # Command-line argument parsing
├── config.rb             # Configuration constants
├── logger.rb             # Logging and debug output
├── path_resolver.rb      # Find log file locations
├── powershell.rb         # Execute PowerShell scripts
├── stats.rb              # Track collection statistics
├── time_parser.rb        # Parse time ranges
├── utils.rb              # Utility functions
├── TSV.rb                # TSV file handling
├── version.rb            # Version info
│
├── collectors/           # Data collection modules
│   ├── windows.rb        # Windows Event Log collector
│   └── files.rb          # Generic file collector
│
└── processors/           # Data processing modules
    ├── alerts.rb         # Alert scanning (find errors)
    ├── reports.rb        # Report generation
    ├── snapshot.rb       # System snapshot
    ├── comparison.rb     # File comparison
    ├── patterns.rb       # Pattern analysis
    └── timeline.rb       # Timeline creation
```

---

## Usage Guide

### Basic Commands

```powershell
# Last 24 hours (most common for incidents)
ruby bin/tripwire.rb --last 1d

# Last 7 days (default)
ruby bin/tripwire.rb --last 1w

# Last 30 days
ruby bin/tripwire.rb --last 1m

# Specific time window
ruby bin/tripwire.rb --start "2025-12-05 10:00:00" --end "2025-12-05 12:00:00"

# Verbose output (see detailed debug logs)
ruby bin/tripwire.rb --last 1d --verbose

# FORENSICS MODE - Collect EVERYTHING (all events, all levels, all files)
ruby bin/tripwire.rb --last 1d --forensics
```

### Advanced Options

```powershell
# FORENSICS MODE - Maximum data collection for deep analysis
# Enables: all-security, all-levels, all-files, verbose
ruby bin/tripwire.rb --last 1d --forensics

# Collect ALL Security events (not just critical ones)
ruby bin/tripwire.rb --last 1d --all-security

# Collect ALL event levels (including verbose/debug)
ruby bin/tripwire.rb --last 1d --all-levels

# Skip Windows events (just get app logs)
ruby bin/tripwire.rb --last 1d --skip-windows

# Run collectors in parallel (faster on slow disks)
ruby bin/tripwire.rb --last 1d --parallel

# Collect all files regardless of timestamp
ruby bin/tripwire.rb --all-files
```

---

## Incident Response Scenarios

### Scenario 1: "The application crashed at 3 PM"

**What you need:** Application logs around that time + system events

```powershell
# Collect 2 hours around the incident (1 hour before, 1 hour after)
ruby bin/tripwire.rb --start "2025-12-05 14:00:00" --end "2025-12-05 16:00:00"

# Open the output folder:
# 1. Look at Reports/ for what went wrong
# 2. Check Alerts/ for error messages
# 3. Review Windows/Application for app events
```

**What to look for:**
- Check `Alerts/` folder - Critical errors are highlighted
- Search for your app name in `Windows/Application/Application.tsv`
- Look for EXCEPTION, FATAL, or ERROR keywords
- Check timestamps before the crash for warnings

---

### Scenario 2: "Someone accessed an account without permission"

**What you need:** Security events + who logged in + when

```powershell
# Collect the full day for context
ruby bin/tripwire.rb --last 1d --all-sec

# Open Windows/Security/Security.tsv and look for:
# - Event 4624: Successful logon (who, when, from where)
# - Event 4625: Failed logon attempts (break-in attempts)
# - Event 4720: New user account created (unauthorized changes)
# - Event 4648: Logon with explicit credentials (suspicious access)
```

**What to look for:**
- Logons at unusual times
- Logons from unusual IP addresses
- Multiple failed logons before a success (brute force)
- Accounts that shouldn't have access

---

### Scenario 3: "Database queries are slow all of a sudden"

**What you need:** PostgreSQL logs + system resource usage

```powershell
ruby bin/tripwire.rb --last 1d

# Open outputs:
# 1. PostgreSQL/PostgreSQL.tsv - Look for slow query warnings
# 2. Windows/System/System.tsv - Look for disk/memory pressure
# 3. Snapshot/ - Check available resources
```

**What to look for:**
- PostgreSQL duration/timing messages
- System disk full errors
- Memory pressure warnings
- Network connectivity issues

---

### Scenario 4: "Service keeps failing - need full forensics"

**What you need:** Everything, with all detail levels

```powershell
# Maximum data collection for deep analysis
ruby bin/tripwire.rb --last 1w --all-sec --all-levels --all-files

# This will take longer but gives complete picture
```

---

## Configuration

Edit `config/config.yml` to customize TripWire for your environment.

### Key Settings

**Log Paths** - Where to find your logs:
```yaml
paths:
  datadog: 'C:/ProgramData/Datadog/logs'
  postgresql: 'C:/Program Files/PostgreSQL/15/data/log'
```

**Event Filtering** - What events to collect:
```yaml
options:
  all_sec: false        # Collect all Security events?
  all_lvl: false        # Collect all event levels?
  skip_windows: false   # Skip Windows Event Log?
  verbose: false        # Show debug output?
```

**Alert Keywords** - What counts as an error:
```yaml
alerts:
  error_keywords:
    - 'FATAL'
    - 'CRITICAL'
    - 'EXCEPTION'
    - 'ERROR'
    # Add your app-specific keywords here
```

See `config/config.yml` for complete reference.

---

## Output

### Folder Structure

```
TripWire_20251212-094806/
├── Windows/                    # Windows Event Logs
│   ├── System/
│   │   └── System.tsv          # Hardware, driver, service events
│   ├── Application/
│   │   └── Application.tsv     # App errors and issues
│   └── Security/
│       └── Security.tsv        # Logins, account changes, etc
│
├── Datadog/                    # Datadog agent logs
│   └── Datadog.tsv
│
├── PostgreSQL/                 # Database logs
│   └── PostgreSQL.tsv
│
├── Alerts/                     # Found errors and warnings
│   ├── alerts_System.tsv
│   ├── alerts_Application.tsv
│   ├── alerts_PostgreSQL.tsv
│   └── alerts_Security.tsv
│
├── Reports/                    # Analysis reports
│   ├── summary_report.tsv
│   └── timeline.tsv
│
├── Snapshot/                   # System state snapshot
│   ├── processes.txt
│   ├── network_connections.txt
│   └── system_info.txt
│
└── SUMMARY.txt                 # Quick reference summary
```

### Output Files Explained

**TSV Files** - Tab-separated values (open in Excel)
- Timestamp | Severity | Message | Source

**Alerts** - Only critical entries
- FATAL, CRITICAL, EXCEPTION, ERROR keywords
- TIMEOUT, CONNECTION FAILED
- Out-of-memory, disk full

**Timeline** - Events ordered by time
- Chronological view of what happened
- Easier to see sequence of events

**SUMMARY.txt** - Quick facts
- Total events collected
- Alerts found
- Time range
- Output location

---

## Troubleshooting

### "Datadog path not resolved"

**Problem:** TripWire couldn't find your Datadog logs

**Solution:**
1. Find where Datadog logs are: `dir C:/ProgramData/Datadog/`
2. Update `config/config.yml`:
   ```yaml
   paths:
     datadog: 'C:/ProgramData/Datadog/logs'
   ```
3. Re-run TripWire

### "PowerShell permission denied"

**Problem:** Windows Event Log requires admin access

**Solution:** 
Run PowerShell as Administrator:
1. Right-click PowerShell
2. Select "Run as administrator"
3. Run TripWire again

### "No events collected"

**Problem:** Time range might be wrong or no events in that period

**Solution:**
1. Try a longer time range: `--last 1w` instead of `--last 1d`
2. Check your date format: `YYYY-MM-DD HH:MM:SS`
3. Run with `--verbose` to see what's happening

### "Output folder too large"

**Problem:** Too much data collected

**Solution:**
- Use shorter time ranges: `--last 1d` instead of `--last 1m`
- Skip Windows events: `--skip-windows`
- Use specific date range instead of `--last`
- Use `exclude_paths` in config to skip large directories

### "Need more help?"

Run with verbose output to see detailed logs:
```powershell
ruby bin/tripwire.rb --last 1d --verbose
```

Check the `debug.log` file in the output folder.

---

## Key Concepts for Learning

### Time Ranges
- Most incidents: **last 24 hours** (`--last 1d`)
- For trending issues: **last week** (`--last 1w`)
- For historical analysis: **last month** (`--last 1m`)
- **Exact window**: `--start "DATE TIME" --end "DATE TIME"`

### Event Severity (Windows)
- **Level 1:** Error (Critical issues)
- **Level 2:** Warning (Potential problems)
- **Level 3:** Information (General activity)
- **Level 4+:** Verbose/Debug (detailed trace info)

By default, TripWire only collects levels 1-3 (errors and warnings). Use `--all-levels` to get everything.

### Security Event IDs
- **4624:** Someone logged in successfully
- **4625:** Failed login attempt (possible attack)
- **4720:** New user created
- **4740:** Account locked (too many failed attempts)

See `config/config.yml` for the complete reference.

### TSV Format
Tab-separated values (like CSV but with tabs). Open in:
- Excel
- Google Sheets  
- Any text editor
- Easy to search and filter

---

## Requirements

- **Windows 10/11** or Windows Server 2016+
- **Ruby 2.6+** (download from ruby-lang.org)
- **PowerShell 5.0+** (comes with Windows)
- **Administrator access** (for Event Log collection)

---

## License

MIT

## Author

Scott Petersen

Built for incident detection, log analysis, and forensics investigations.

---

## Next Steps

1. Read through `config/config.yml` to understand your setup
2. Try a test run: `ruby bin/tripwire.rb --last 1d`
3. Explore the output folder structure
4. When a real incident happens, you'll know exactly what to do

# TripWire Enhanced - Implementation Guide

## Overview
TripWire v3.2 now includes comprehensive debug logging (Ruby 2.3.3 compatible) and **VACUUM mode** for automatic log discovery and collection across the entire system.

## New Features

### 1. VACUUM Mode 🔍
**Automatically discovers and collects ALL logs on the system**

- Auto-detects 15+ application types (databases, web servers, monitoring tools, etc.)
- Intelligent categorization by service type
- Generates comprehensive inventory
- Works out-of-the-box with zero configuration

**Quick Start:**
```powershell
# Collect all logs from last 24 hours
ruby tripwire.rb --vacuum --last 24h

# Deep scan for comprehensive coverage
ruby tripwire.rb --vacuum --vacuum-deep --verbose --last 24h
```

**See:** `VACUUM_MODE_DOCS.md` and `VACUUM_QUICK_REFERENCE.md` for details

### 2. Enhanced Debug Logging
**Controlled by --verbose flag**

When enabled, creates `debug.log` with:
- Every function entry/exit with parameters and results
- Every file operation (read, write, create, delete)
- Every log line processed **with full content** (up to 500 chars)
- All timestamp parsing attempts (success/failure)
- PowerShell execution details (scripts, output, timing)
- Path resolution steps (what was tried, found)
- Alert keyword matching (what matched, why skipped)
- Variable states at key decision points

## What Was Changed

### New Files
1. **`lib/collectors/vacuum.rb`** - VACUUM mode collector
   - Auto-discovers logs from 15+ applications
   - Categorizes by service type
   - Generates inventory and metadata

### Modified Files

#### 1. **`lib/logger.rb`** - Enhanced Logger
- Added `debug_log()` method with context tags
- Added `log_enter()` / `log_exit()` for function tracing
- Added `log_file_op()` for all file operations
- Added `log_line_processing()` for detailed line-by-line logging with full content
- Added `log_timestamp_parse()` for timestamp parsing attempts
- Added `log_powershell()` for PowerShell execution details
- Added `log_path_resolution()` for path discovery steps
- Added `log_alert_check()` for alert matching details
- Added `log_state()` for variable snapshots
- All methods include timestamps (ms precision) and thread IDs

#### 2. **`bin/tripwire.rb`** - Main Runner
- Changed heredocs from `<<~` to `<<-` for Ruby 2.3.3 compatibility
- Added `log_enter/log_exit` around all major methods
- Added `log_state()` calls for key variables
- Added detailed error logging with full backtraces
- Setup debug.log in output directory
- Integrated VACUUM mode
- Updated summary for VACUUM stats

#### 3. **`lib/collectors/files.rb`** - File Collector
- Logs every file discovered with metadata (size, mtime)
- Logs each file processed/skipped with reasons
- Logs every line with full content (timestamp, severity, content)
- Logs parse successes/failures
- Logs lines added vs skipped with counts

#### 4. **`lib/utils.rb`** - Utility Functions
- Enhanced `parse_timestamp()` with success/failure logging
- Logs which pattern matched for timestamps
- Enhanced `severity()` with detection logging
- Shows sample content for each classification

#### 5. **`lib/powershell.rb`** - PowerShell Execution
- Logs PowerShell discovery attempts
- Logs temp script creation
- Logs execution time and output
- Logs stdout/stderr (first 500 chars)
- Logs exit codes and errors

#### 6. **`lib/path_resolver.rb`** - Path Discovery
- Logs all path resolution steps
- Logs configured, default, and discovered paths
- Logs BFS search progress (every 100 dirs)
- Logs directory matches with details

#### 7. **`lib/processors/alerts.rb`** - Alert Detection
- Logs pattern matching attempts
- Logs matched keywords for each alert
- Logs full message content
- Logs timestamp parsing with reasons for failures
- Logs out-of-range and bad timestamp details

#### 8. **`lib/cli.rb`** - Command Line Interface
- Added `--vacuum` flag for auto-discovery mode
- Added `--vacuum-deep` for deep scanning (6 levels vs 3)
- Added `--vacuum-max-generic N` to control generic log limit
- Reorganized help output with sections

#### 9. **`lib/stats.rb`** - Statistics
- Added setter method for VACUUM stats
- Tracks vacuum-specific metrics

## Ruby 2.3.3 Compatibility Changes

1. **Heredocs**: Changed `<<~HEREDOC` to `<<-HEREDOC` (squiggly heredoc was added in Ruby 2.3)
2. **All syntax tested** for 2.3.3 compatibility

## Usage

### Standard Mode (Unchanged)
```powershell
# Normal run (no debug log)
ruby tripwire.rb --last 24h

# With comprehensive logging
ruby tripwire.rb --last 24h --verbose
```

### New VACUUM Mode
```powershell
# Auto-discover all logs
ruby tripwire.rb --vacuum --last 24h

# Deep scan with debug logging
ruby tripwire.rb --vacuum --vacuum-deep --verbose --last 24h

# Limit generic logs
ruby tripwire.rb --vacuum --vacuum-max-generic 50 --last 24h
```

## Output Files

### Standard Mode
```
TripWire_YYYYMMDD-HHMMSS/
├── Windows/
├── Datadog/
├── PostgreSQL/
├── Alerts/
├── Reports/
├── Snapshot/
├── debug.log        # NEW: With --verbose
├── summary.log
└── SUMMARY.txt
```

### VACUUM Mode
```
TripWire_YYYYMMDD-HHMMSS/
├── Vacuum/
│   ├── INVENTORY.txt      # NEW: Master inventory
│   ├── Database/          # NEW: Organized by category
│   │   └── postgresql_0/
│   │       ├── postgresql_0.tsv
│   │       └── metadata.txt    # NEW: Per-source metadata
│   ├── WebServer/
│   ├── Monitoring/
│   └── Unknown/
├── Alerts/
├── Reports/
├── debug.log        # With --verbose
├── summary.log
└── SUMMARY.txt
```

## Debug Log Format

```
[2024-01-19 14:23:45.123] [a3f2c1] [FILES] >>> ENTER process_file | params: {:file=>"datadog.log"}
[2024-01-19 14:23:45.125] [a3f2c1] [PARSE] datadog.log line 1: timestamp=2024-01-18 10:30:22, severity=ERROR, length=234
[2024-01-19 14:23:45.125] [a3f2c1] [PARSE] Content: 2024-01-18 10:30:22 ERROR [database] Connection timeout...
[2024-01-19 14:23:45.126] [a3f2c1] [TIMESTAMP] SUCCESS: 2024-01-18 10:30:22 (via ISO8601)
[2024-01-19 14:23:45.127] [a3f2c1] [SEVERITY] Detected: ERROR | Line: 2024-01-18 10:30:22 ERROR [database]...
[2024-01-19 14:23:45.128] [a3f2c1] [FILES] <<< EXIT process_file | result: {:lines_added=>1523, :lines_skipped=>42}
```

### Log Context Tags:
- `[RUNNER]` - Main application flow
- `[VACUUM]` - VACUUM mode operations
- `[FILES]` - File collection operations
- `[PARSE]` - Line parsing with full content
- `[TIMESTAMP]` - Timestamp parsing attempts
- `[SEVERITY]` - Severity detection
- `[PWSH]` - PowerShell operations
- `[PATH]` - Path resolution
- `[ALERTS]` - Alert detection
- `[FILE]` - File I/O operations

## What Gets Logged (with --verbose)

### File Processing:
```
[PARSE] datadog.log line 1523: timestamp=2024-01-18 10:30:22, severity=ERROR, length=234
[PARSE] Content: 2024-01-18 10:30:22 ERROR [database] Connection timeout after 30s to postgres://prod-db:5432
```

### Alert Detection:
```
[ALERTS] MATCH 42: keywords=["error", "timeout"]
[ALERTS] Message: Connection timeout after 30s to postgres://prod-db:5432
[ALERTS] OUT_OF_RANGE: 2024-01-15 10:30:22 not in [2024-01-18 00:00:00, 2024-01-19 00:00:00]
```

### VACUUM Discovery:
```
[VACUUM] Scanning: C:/ProgramData
[VACUUM] Match: C:/ProgramData/PostgreSQL/15/data/log
[VACUUM] postgresql: 23 files, 456.78 MB
[VACUUM] Found 8 log sources
```

## Performance Impact

- **Without --verbose**: No impact (debug logging disabled)
- **Without --vacuum**: Unchanged from original
- **With --verbose**: Slower execution, large debug.log files (100+ MB possible)
- **With --vacuum**: Depends on system size and depth setting
  - Standard scan: Moderate (searches 3 levels deep)
  - Deep scan: Slower (searches 6 levels deep)

## Command Line Reference

### Time Range Options
```
--last D         Duration (6h, 2d, 1w, 1m)
--back D         Offset (2m1w3d)
--today          Collect today's logs
--yesterday      Collect yesterday's logs
```

### Collection Options
```
--vacuum              VACUUM MODE: Auto-discover all logs
--vacuum-deep         Deep scan (6 levels vs 3)
--vacuum-max-generic  Max generic log files (default: 100)
--skip-windows        Skip Windows event collection
--skip-snapshot       Skip system snapshot
--all-files           Include all files regardless of timestamp
```

### Windows Event Options
```
--parallel        Run Windows collection in parallel
--all-security    Collect all Security events
--all-levels      Collect all event levels
```

### Path Options
```
--datadog P       Datadog log path
--postgres P      PostgreSQL log path
```

### Output Options
```
--verbose         Enable detailed debug logging
```

## Pattern Analysis Benefits

With full content logging, you can:
1. See exactly what content matched/didn't match alert keywords
2. Identify timestamp parsing issues with actual content
3. Debug severity classification edge cases
4. Track down missing/incorrect paths
5. Analyze PowerShell failures with full context
6. See which lines were processed vs skipped and why

## Example Analysis Queries

Search debug.log for specific patterns:

```powershell
# Find all ERROR lines processed
Select-String -Path debug.log -Pattern "\[SEVERITY\] Detected: ERROR"

# Find all failed timestamp parses
Select-String -Path debug.log -Pattern "\[TIMESTAMP\] FAILED"

# Find all alert matches
Select-String -Path debug.log -Pattern "\[ALERTS\] MATCH"

# Find VACUUM discoveries
Select-String -Path debug.log -Pattern "\[VACUUM\].*Found"
```

## Files to Replace

Replace/add these files in your TripWire installation:

**Modified:**
1. `lib/logger.rb` - Enhanced logger
2. `bin/tripwire.rb` - Main script
3. `lib/collectors/files.rb` - File collector
4. `lib/utils.rb` - Utilities
5. `lib/powershell.rb` - PowerShell module
6. `lib/path_resolver.rb` - Path resolver
7. `lib/processors/alerts.rb` - Alert processor
8. `lib/cli.rb` - Command line interface
9. `lib/stats.rb` - Statistics tracker

**New:**
10. `lib/collectors/vacuum.rb` - VACUUM mode collector

All other files remain unchanged.

## Documentation Files

- `ENHANCED_LOGGING_GUIDE.md` (this file) - Overall implementation guide
- `VACUUM_MODE_DOCS.md` - Comprehensive VACUUM mode documentation
- `VACUUM_QUICK_REFERENCE.md` - Quick reference for VACUUM mode

## Support

For questions or issues:
1. Run with `--verbose` to see detailed logging
2. Check `debug.log` for operation details
3. Review INVENTORY.txt in VACUUM mode to see what was found
4. Check metadata.txt files for per-source details
