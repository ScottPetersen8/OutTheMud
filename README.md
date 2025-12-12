# TripWire v3.2

A simple incident detection system that collects Windows events, Datadog logs, and PostgreSQL logs for a specific time range.

## What It Does

- Collects Windows Event Viewer logs (System, Application, Security)
- Collects Datadog log files
- Collects PostgreSQL log files
- Filters everything by date/time range
- Finds errors and warnings
- Creates organized reports

## Requirements

- Windows OS
- Ruby installed
- PowerShell (comes with Windows)

## Installation

1. Clone or download this repository
2. Edit `config/config.yml` with your log paths:
```yaml
paths:
  datadog: 'C:/ProgramData/Datadog/logs'
  postgresql: 'C:/Program Files/PostgreSQL/15/data/log'
```

## Usage

### Basic Usage

Collect logs from the last week:
```powershell
ruby bin/tripwire.rb --last 1w
```

Collect logs from the last 24 hours:
```powershell
ruby bin/tripwire.rb --last 1d
```

Collect logs from the last month:
```powershell
ruby bin/tripwire.rb --last 1m
```

### Specific Date Range

```powershell
ruby bin/tripwire.rb --start "2025-12-01" --end "2025-12-12"
```

### Options

- `--last 1d` - Last 24 hours
- `--last 1w` - Last 7 days (default)
- `--last 1m` - Last 30 days
- `--verbose` - Show detailed debug output
- `--skip-windows` - Skip Windows event collection
- `--skip-snapshot` - Skip system snapshot

## Output

Creates a timestamped folder with all collected data:

```
TripWire_20251212-094806/
├── Windows/
│   ├── System/System.tsv
│   ├── Application/Application.tsv
│   └── Security/Security.tsv
├── Datadog/
│   └── Datadog.tsv
├── PostgreSQL/
│   └── PostgreSQL.tsv
├── Alerts/
│   └── alerts_*.tsv
├── Reports/
├── Snapshot/
└── SUMMARY.txt
```

## What Gets Collected

### Windows Events
- System errors and warnings
- Application errors and warnings  
- Security events (logons, logoffs, account changes)

### Datadog Logs
- All log files in configured Datadog directory
- Filtered by timestamp

### PostgreSQL Logs
- All log files in configured PostgreSQL directory
- Filtered by timestamp

## Example Output

```
[10:18:06] Windows System...
[10:18:07]   ✓ 1642 events
[10:18:07] Windows Application...
[10:18:08]   ✓ 241 events
[10:18:08] Windows Security...
[10:18:09]   ✓ 300 events
[10:18:09] Datadog...
[10:18:10]   ✓ 0 files, 0 lines
[10:18:10] PostgreSQL...
[10:18:19]   ✓ 19 files, 44 lines
[10:18:19] Scanning for alerts...
[10:18:19]    9 → alerts_PostgreSQL.tsv

═════════════════════════════════════════
TripWire v3.2 - Summary
═════════════════════════════════════════
Duration: 12.45s
Range: 2025-12-05 09:48 → 2025-12-12 09:48
Files: 19 | Lines: 44 | Errors: 3 | Alerts: 9
Output: C:/users/scottp/TripWire_20251212-094806
═════════════════════════════════════════
```

## Configuration

Edit `config/config.yml` to customize:

- Log file paths
- Security event IDs to collect
- Search patterns
- Default options

## Troubleshooting

**"Datadog path not resolved"** - Update the `datadog` path in `config/config.yml`

**"PostgreSQL path not resolved"** - Update the `postgresql` path in `config/config.yml`

**No Windows events collected** - Run PowerShell as Administrator

**Need more info?** - Run with `--verbose` flag

## License

MIT

## Author

Scott Petersen

Created for incident detection and log analysis.