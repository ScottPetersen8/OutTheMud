# TripWire v2

**Incident Response Log Collector**

Automatically collects Windows events, Datadog logs, and PostgreSQL logs for incident response analysis.

---

## Quick Start

```bash
ruby bin\tripwire.rb
```

Collects logs from the last 24 hours. Output saved to `TripWire_YYYYMMDD-HHMMSS/`

---

## What You Get

```
TripWire_20260122-220258/
├── SUMMARY.txt                    ← Quick overview
├── debug.log                      ← Detailed execution log
├── Windows/
│   ├── System/System.tsv          ← All System events
│   ├── Application/Application.tsv ← All Application events
│   └── Security/Security.tsv      ← All Security events
├── Datadog/
│   └── Datadog.tsv                ← All Datadog logs (if found)
├── PostgreSQL/
│   └── PostgreSQL.tsv             ← All PostgreSQL logs (if found)
├── Alerts/
│   ├── alerts_System.tsv          ← Critical System issues
│   └── alerts_Application.tsv     ← Critical Application issues
└── Snapshot/
    ├── disk.tsv                   ← Disk usage
    └── mem.tsv                    ← Memory info
```

---

## TSV Format

All data is in TSV (tab-separated) format for easy analysis in Excel/Python/SQL:

```
timestamp           severity  message                      source        file_path
2026-01-22 10:45:30 ERROR     Service failed to start      MyApp.log     C:/Logs/MyApp.log
2026-01-22 10:45:35 WARNING   Connection timeout           Database.log  C:/Data/db.log
```

**Columns:**
- `timestamp` - When the event occurred
- `severity` - ERROR, WARNING, INFO, etc.
- `message` - The log message
- `source` - Which log file it came from
- `file_path` - Full path to source file

---

## Common Tasks

### Collect Logs from Specific Time Range

Default is last 24 hours. To change:

```bash
# Last 7 days
ruby bin\tripwire.rb --last 7d

# Last 12 hours
ruby bin\tripwire.rb --last 12h

# Specific time window
ruby bin\tripwire.rb --start "2026-01-20 14:00" --end "2026-01-20 16:00"
```

### Analyze Results

1. **Start with SUMMARY.txt** - Quick overview of what was collected
2. **Check Alerts/** - Automatic detection of suspicious activity
3. **Review Windows logs** - Timeline of system events
4. **Correlate timestamps** - See what happened when across all systems

### Open in Excel

TSV files open directly in Excel:
1. Double-click any `.tsv` file
2. Excel will auto-detect columns
3. Use filters and sorting to analyze

### Import to Database

```sql
-- PostgreSQL example
COPY events FROM 'C:/TripWire_20260122-220258/Windows/System/System.tsv' 
WITH (FORMAT CSV, DELIMITER E'\t', HEADER);
```

---

## What It Collects

### Windows Events (always)
- **System** - Hardware, drivers, services
- **Application** - App crashes, errors
- **Security** - Logins, logouts, permissions (if admin)

### Datadog (if installed)
Searches these locations:
- `C:/ProgramData/Datadog`
- `C:/Program Files/Datadog`
- `/var/log/datadog`
- `/opt/datadog`

### PostgreSQL (if installed)
Searches these locations:
- `C:/Program Files/PostgreSQL`
- `C:/ProgramData/PostgreSQL`
- `/var/log/postgresql`
- `/var/lib/postgresql`

---

## Alerts

TripWire automatically scans for suspicious patterns:

### Critical Keywords
- `FATAL`, `CRITICAL`, `EXCEPTION`
- `TIMEOUT`, `DENIED`, `UNAUTHORIZED`
- `FAILED`, `FAILURE`, `CRASHED`
- `DEADLOCK`, `CORRUPT`

### Event IDs (Windows)
- **4625** - Failed login
- **4740** - Account lockout
- **7034** - Service crashed
- **1000** - Application error
- **1001** - Application hang
- And 30+ more...

All matches saved to `Alerts/` folder.

---

## Configuration

TripWire works out-of-the-box with no configuration. Optional customization:

### config/config.yml

```yaml
# Add custom log sources
log_sources:
  MyApp:
    path: "C:/Apps/MyApp/logs"
  
  CustomDB:
    path: "/var/log/mydb"

# Options (all optional)
options:
  all_sec: false        # Collect ALL Security events (slower)
  all_lvl: false        # Collect INFO events (more noise)
  verbose: false        # Detailed debug output
  analyze: true         # Enable alert detection
  snapshot: true        # Capture system info
```

---

## Requirements

- **Ruby** 2.6+ (tested on 3.0+)
- **Windows** for Event Viewer collection
- **Admin rights** for Security events (optional)

No external gems required - uses only Ruby standard library.

---

## Troubleshooting

### "No events collected"
- Check time range: `--last 7d` to expand search
- Run as Administrator for Security events
- Verify services are running: Event Log service

### "Datadog/PostgreSQL not found"
- Normal if not installed
- Empty TSV files still created for reference
- Check file paths in code if installed in custom location

### "Permission denied"
- Run PowerShell as Administrator
- Some Security events require admin rights

### "Slow collection"
- Use shorter time range: `--last 12h`
- Disable all Security events: don't use `--all-sec`
- Large logs take time (expected)

---

## Output Files

### SUMMARY.txt
Quick overview:
- How many events collected
- Time range covered
- Critical alerts found
- Execution time

### debug.log
Detailed execution log:
- What was collected
- Which paths were searched
- Any errors encountered
- Timing information

### TSV Files
All event data in tab-separated format for analysis.

---

## For Incident Response

**Workflow:**

1. **Incident detected** → Note the time
2. **Run TripWire** → `ruby bin\tripwire.rb --start "incident time" --last 2h`
3. **Check Alerts** → `Alerts/` folder for automatic detections
4. **Build Timeline** → Open TSVs in Excel, sort by timestamp
5. **Correlate** → Match timestamps across Windows/Datadog/PostgreSQL
6. **Investigate** → Look for patterns before/after incident
7. **Report** → Share output folder with team

**Example: Service Outage**

```bash
# Service went down at 2:30 PM
ruby bin\tripwire.rb --start "2026-01-22 14:00" --end "2026-01-22 15:00"

# Check results:
# 1. Alerts/alerts_System.tsv - Service crash?
# 2. Windows/System/System.tsv - Driver issues?
# 3. PostgreSQL/PostgreSQL.tsv - Database errors?
# 4. Look for patterns 14:25-14:35
```

---

## Git Branches

This repo has multiple versions:

- **v0-original** - Original TripWire
- **master** - v1 with sniffer/vacuum flags
- **v2-simplified** - ⭐ This version (recommended)
- **v3-incident-response** - Advanced features (coming soon)

Switch versions:
```bash
git checkout v2-simplified  # This version
git checkout master         # v1
```

---

## Support

- Check **00_READ_ME_FIRST.md** for quick start
- See **START_HERE.md** for detailed guide
- Open GitHub issues for bugs

---

**Version:** v2-simplified  
**Status:** ✅ Production Ready  
**License:** MIT
