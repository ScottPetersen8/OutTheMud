TripWire – Incident Detection & Log Collection

Version: 2.1 
Language: Ruby 2.5+

TripWire is a cross-system incident response helper that collects, filters, and analyses logs from Windows, PostgreSQL and Datadog.
It automatically builds a complete incident package for review.

# Features

Windows Event Log collection (Security/System/Application)

PostgreSQL and Datadog log harvesting

Keyword-based alert extraction

Time-window filtering (--last, --back, etc.)

Parallel Windows log collection

TSV reporting (with sanitization)

System snapshots (optional)

Clean folder structure per incident

Summary logging and statistics

 Installation

Install Ruby 2.5+

Clone or copy the script

Install dependencies (all are Ruby standard library)

Run it with:

ruby TripWire.rb

# Time Windows

Examples:

--last 6h        # Last 6 hours
--last 2d        # Last 2 days
--last 1w        # Last 1 week
--back 2m1w3d    # 2 months, 1 week, 3 days ago
--today
--yesterday


If no option is provided → default is last 24 hours.

# Usage Examples

Collect last 6 hours:

ruby TripWire.rb --last 6h


Yesterday's logs with Windows logs skipped:

ruby TripWire.rb --yesterday --skip-windows


Collect all security events (slow):

ruby TripWire.rb --all-security-events


Parallel mode:

ruby TripWire.rb --last 24h --parallel


Custom security Event IDs:

ruby TripWire.rb --security-ids 4625,4720


Include a TSV sample:

ruby TripWire.rb --sample-tsv logs/example.tsv

# Output Structure
TripWire_YYYYMMDD-HHMMSS/
  WindowsEvent/
  Datadog/
  PostgreSQL/
  ExtractedAlerts/
  ReadableReports/
  SystemSnapshot/
  TripWire_Summary.log

# Configuration File

You can override paths using:

--config custom_paths.rb


Example config:

LOG_PATHS[:postgresql] = "D:/PG/logs"
LOG_PATHS[:datadog]    = "D:/DD/logs"

# TSV Format

TripWire’s TSV module ensures:

No tabs, newlines, invalid characters

UTF-8 output

Safe parsing of malformed lines

# Exit Handling

Press Ctrl + C
TripWire will cleanly exit and notify the user.

# License

Internal tool — unrestricted use for support and IR teams.