line = "INFO  2025-11-23 14:42:50.693 +0200 [Thread-1] Stopped ServerConnector"
ts = parse_timestamp_from_line(line)
puts ts.inspect
