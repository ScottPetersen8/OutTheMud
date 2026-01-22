# TripWire v2 - Quick Start

## What This Does

TripWire automatically collects logs from your Windows machine for incident response:

- ✅ **Windows Events** (System, Application, Security)
- ✅ **Datadog Logs** (if installed)
- ✅ **PostgreSQL Logs** (if installed)
- ✅ **Automatic Alerts** (detects suspicious activity)
- ✅ **System Snapshot** (disk, memory info)

## Run It

```bash
ruby bin\tripwire.rb
```

That's it! No flags needed.

## Output

```
TripWire_20260122-220258/
├── SUMMARY.txt                    ← Quick overview
├── debug.log                      ← Detailed execution log
├── Windows/
│   ├── System/System.tsv          ← All System events
│   ├── Application/Application.tsv ← All Application events
│   └── Security/Security.tsv      ← All Security events
├── Datadog/
│   └── Datadog.tsv                ← All Datadog logs
├── PostgreSQL/
│   └── PostgreSQL.tsv             ← All PostgreSQL logs
├── Alerts/
│   ├── alerts_System.tsv          ← Suspicious System events
│   └── alerts_Application.tsv     ← Suspicious Application events
└── Snapshot/
    ├── disk.tsv                   ← Disk usage
    └── mem.tsv                    ← Memory info
```

## What It Collects

**Windows Events** (last 24 hours by default)
- System errors and warnings
- Application crashes
- Security events (logins, privilege changes)

**Application Logs** (if found)
- Searches known Datadog/PostgreSQL locations
- Consolidates all files into one TSV per service
- Parses timestamps, severity, messages

**Alerts** (automatic)
- Failed login attempts
- Service failures
- Critical errors
- High severity events

## TSV Format

Every TSV has the same columns for easy analysis:

```
timestamp | severity | message | source | file_path
```

**Example:**
```
2026-01-22 10:45:30 | ERROR | Service failed to start | MyApp.log | C:/Logs/MyApp.log
```

## For Incident Response

1. **Run TripWire** → Collect all logs
2. **Check SUMMARY.txt** → See what was found
3. **Open Alerts/** → Start with suspicious activity
4. **Analyze TSVs** → Timeline of events across all systems
5. **Correlate** → See what happened when

## Need Help?

- **START_HERE.md** - More detailed guide
- **README.md** - Full documentation

---

**Version:** TripWire v2-simplified  
**Branch:** v2-simplified  
**Status:** ✅ Ready for production

