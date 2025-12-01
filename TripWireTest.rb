#!/usr/bin/env ruby
# incident_collector_enhanced.rb
# Enhanced incident collector with improved error handling, progress reporting,
# configuration management, and optional features.

require 'fileutils'
require 'time'
require 'csv'
require 'optparse'
require 'tempfile'
require 'logger'

# -----------------------------
# Configuration / Defaults
# -----------------------------
DEFAULT_HOURS = 24
KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
ROOT_BASE = Dir.pwd
SAMPLE_DATADOG_CSV = '/mnt/data/Datadog.csv'

# Configuration for log paths (easy to customize per environment)
LOG_PATHS = {
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
  datadog: 'C:/ProgramData/Datadog/logs',
  imqs: 'C:/imqsvar/logs/services/pcs'
}

# -----------------------------
# Logging setup
# -----------------------------
$logger = Logger.new(STDOUT)
$logger.level = Logger::INFO
$logger.formatter = proc do |severity, datetime, progname, msg|
  "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity.ljust(5)} | #{msg}\n"
end

# -----------------------------
# CLI Options
# -----------------------------
options = {
  mode: :default,
  hours: DEFAULT_HOURS,
  last_raw: nil,
  back_raw: nil,
  verbose: false,
  all_files: false,
  sample_csv: nil,
  skip_windows: false,
  skip_snapshot: false,
  config_file: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby incident_collector_enhanced.rb [options]"

  opts.on("--last DURATION", "Collect logs from the last duration (e.g., 6h, 2d). h=hours, d=days") do |dur|
    options[:mode] = :last
    options[:last_raw] = dur
  end

  opts.on("--back SPEC", "Collect logs starting from a past date offset (e.g., 2m1w3d)") do |raw|
    options[:mode] = :back
    options[:back_raw] = raw
  end

  opts.on("--today", "Collect logs for today (since midnight)") do
    options[:mode] = :today
  end

  opts.on("--yesterday", "Collect logs for yesterday (00:00-23:59)") do
    options[:mode] = :yesterday
  end

  opts.on("--all-files", "Include all files regardless of modification time") do
    options[:all_files] = true
  end

  opts.on("--verbose", "Enable verbose output") do
    options[:verbose] = true
    $logger.level = Logger::DEBUG
  end

  opts.on("--skip-windows", "Skip Windows Event Log collection") do
    options[:skip_windows] = true
  end

  opts.on("--skip-snapshot", "Skip system snapshot collection") do
    options[:skip_snapshot] = true
  end

  opts.on("--sample-csv PATH", "Include a specific CSV file in collection") do |path|
    options[:sample_csv] = path
  end

  opts.on("--config FILE", "Load custom log paths from config file") do |file|
    options[:config_file] = file
  end

  opts.on("-h", "--help", "Show this help") do
    puts opts
    puts "\nExamples:"
    puts "  ruby incident_collector_enhanced.rb --last 6h"
    puts "  ruby incident_collector_enhanced.rb --yesterday --verbose"
    puts "  ruby incident_collector_enhanced.rb --back 2m1w3d"
    puts "  ruby incident_collector_enhanced.rb --today --skip-windows"
    exit
  end
end.parse!

# -----------------------------
# Load custom config if provided
# -----------------------------
if options[:config_file] && File.exist?(options[:config_file])
  begin
    eval(File.read(options[:config_file]))
    $logger.info "Loaded configuration from #{options[:config_file]}"
  rescue => e
    $logger.error "Failed to load config file: #{e.message}"
    exit(1)
  end
end

# -----------------------------
# Time range calculation
# -----------------------------
now = Time.now
start_time = nil
end_time = now

def parse_back_range(back_raw)
  unless back_raw =~ /^(\d+[mwd])+$/i
    raise ArgumentError, "Invalid --back format. Use examples like: 2m1w3d, 4m, 3w2d"
  end

  start_date = Date.today
  back_raw.scan(/(\d+)([mwd])/i) do |amount, unit|
    amount = amount.to_i
    case unit.downcase
    when 'm'
      start_date = start_date << amount
    when 'w'
      start_date -= (amount * 7)
    when 'd'
      start_date -= amount
    end
  end

  start_time = Time.new(start_date.year, start_date.month, start_date.day, 0, 0, 0)
  end_time = start_time + 24*3600 - 1
  return start_time, end_time
end

case options[:mode]
when :today
  start_time = Time.new(now.year, now.month, now.day, 0, 0, 0)
  end_time = start_time + 24*3600 - 1
when :yesterday
  midnight = Time.new(now.year, now.month, now.day, 0, 0, 0)
  start_time = midnight - 24*3600
  end_time = midnight - 1
when :last
  raw = options[:last_raw] || ""
  if raw =~ /^(\d+)([hdw])$/i
    amount, unit = $1.to_i, $2.downcase
    start_time = case unit
                 when 'h' then now - amount*3600
                 when 'd' then now - amount*24*3600
                 when 'w' then now - amount*7*24*3600
                 end
    end_time = now
  else
    $logger.error "Invalid --last format. Use examples like 6h, 2d, 1w"
    exit(1)
  end
when :back
  begin
    start_time, end_time = parse_back_range(options[:back_raw])
  rescue ArgumentError => e
    $logger.error e.message
    exit(1)
  end
else
  start_time = now - DEFAULT_HOURS*3600
  end_time = now
end

# -----------------------------
# Setup output directory structure
# -----------------------------
incident_time = Time.now
ROOTDIR = File.join(ROOT_BASE, "incident_collection_#{incident_time.strftime('%Y%m%d-%H%M%S')}")
FileUtils.mkdir_p(ROOTDIR)

FOLDERS = {
  windows: File.join(ROOTDIR, 'WindowsEvent'),
  datadog: File.join(ROOTDIR, 'Datadog'),
  postgresql: File.join(ROOTDIR, 'PostgreSQL'),
  imqs: File.join(ROOTDIR, 'IMQS'),
  extracted: File.join(ROOTDIR, 'ExtractedAlerts'),
  readable: File.join(ROOTDIR, 'ReadableReports'),
  snapshots: File.join(ROOTDIR, 'SystemSnapshot')
}
FOLDERS.each_value { |p| FileUtils.mkdir_p(p) }

# Create summary log
SUMMARY_LOG = File.join(ROOTDIR, 'collection_summary.log')
$summary_logger = Logger.new(SUMMARY_LOG)
$summary_logger.formatter = proc { |severity, datetime, progname, msg| "#{msg}\n" }

# -----------------------------
# Statistics tracking
# -----------------------------
$stats = {
  files_processed: 0,
  lines_processed: 0,
  errors_found: 0,
  warnings_found: 0,
  alerts_extracted: 0,
  processing_errors: 0,
  start_time: Time.now
}

def record_stat(key, increment = 1)
  $stats[key] ||= 0
  $stats[key] += increment
end

# -----------------------------
# Helper functions
# -----------------------------
TIMESTAMP_PATTERNS = [
  /(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)/,
  /(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: \+\d{4})?(?: UTC)?/,
  /(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
  /(?<ts>\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2})/,
  /^\s*(?:INFO|WARN|ERROR|DEBUG|TRACE)\s+(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+\-]\d{4})?)/x
]

def parse_timestamp_from_line(line)
  return nil if line.nil?

  TIMESTAMP_PATTERNS.each do |pat|
    m = pat.match(line)
    next unless m && m[:ts]

    ts_str = m[:ts].to_s.strip.gsub(/\s+UTC$/, '')
    begin
      return Time.parse(ts_str)
    rescue ArgumentError, TypeError
      next
    end
  end

  nil
end

def normalize_severity(line, csv_severity = nil)
  if csv_severity && csv_severity.to_s.strip != ''
    return csv_severity.to_s.upcase
  end

  if line =~ /^\s*(INFO|WARN|ERROR|DEBUG|TRACE)\b/i
    return $1.upcase
  end

  case line
  when /\b(ERROR|ERR|FATAL|SEVERE|CRITICAL)\b/i then 'ERROR'
  when /\b(WARN|WARNING)\b/i then 'WARN'
  when /\b(INFO|INFORMATION)\b/i then 'INFO'
  when /\b(DEBUG|TRACE)\b/i then 'DEBUG'
  else 'INFO'
  end
end

def tidy(msg, max_len = 1000)
  return '' if msg.nil?
  s = msg.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
  s = s.gsub(/\r?\n/, ' ').strip
  s.length > max_len ? (s[0...max_len] + '...') : s
end

def run_powershell(script, verbose: false)
  tf = Tempfile.new(['psscript', '.ps1'])
  tf.write(script)
  tf.close

  ps_exe = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  cmd = "\"#{ps_exe}\" -NoProfile -ExecutionPolicy Bypass -File \"#{tf.path}\""

  $logger.debug "[PS] Running: #{cmd}" if verbose
  success = system(cmd)

  unless success
    $logger.error "PowerShell command failed (exit=#{$?.exitstatus rescue 'unknown'})"
    record_stat(:processing_errors)
  end

  success
ensure
  tf.unlink if tf
end

# -----------------------------
# Collection functions
# -----------------------------
def collect_windows_events(log, hours, root, verbose: false)
  out_dir = File.join(root, log)
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{log}_events.csv")

  $logger.info "Collecting Windows #{log} events (last #{hours}h)"

  File.open(csv_file, 'w', encoding: 'utf-8') do |f|
    f.puts "TimeCreated,Id,LevelDisplayName,ProviderName,Message"
  end

  (0...hours).each do |h|
    $logger.debug "  Processing hour #{h + 1}/#{hours}..." if verbose

    ps = <<-PS
$start = (Get-Date).AddHours(-#{h+1})
$end   = (Get-Date).AddHours(-#{h})
$filter = @{LogName='#{log}'; StartTime=$start; EndTime=$end}
try {
  $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message
  if ($null -ne $events -and $events.Count -gt 0) {
    $events | Export-Csv -Path '#{csv_file}' -NoTypeInformation -Encoding utf8 -Append
  }
} catch {
  # Silently ignore if no events in this hour
}
PS

    run_powershell(ps, verbose: verbose)
  end

  if File.exist?(csv_file)
    record_stat(:files_processed)
    line_count = File.readlines(csv_file).count - 1
    record_stat(:lines_processed, line_count)
    $summary_logger.info "Collected #{line_count} #{log} events"
  end
end

def collect_logs_from_dir(name, path, start_time, end_time, root, all_files: false, verbose: false)
  out_dir = File.join(root, name)
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{name}.csv")

  $logger.info "Collecting logs from #{name} (#{path})"

  unless Dir.exist?(path)
    File.write(csv_file, "timestamp,severity,log_line,source\n")
    $logger.warn "Directory #{path} does not exist. Skipping."
    $summary_logger.info "#{name}: directory not found"
    return
  end

  rows = [["timestamp","severity","log_line","source"]]
  files_found = 0
  files_processed = 0

  Dir.glob(File.join(path, '*')).sort.each do |file|
    next unless File.file?(file)
    files_found += 1

    unless all_files
      file_age_hours = (Time.now - File.mtime(file)) / 3600.0
      next if file_age_hours > ((end_time - start_time) / 3600.0)
    end

    $logger.debug "  Processing: #{File.basename(file)}" if verbose
    files_processed += 1

    begin
      line_count = 0
      matched_lines = 0

      File.foreach(file, encoding: 'bom|utf-8') do |line|
        line_count += 1
        next if line.strip.empty?

        parsed_ts = parse_timestamp_from_line(line)
        used_ts = parsed_ts || File.mtime(file) || Time.now

        if used_ts >= start_time && used_ts <= end_time
          matched_lines += 1
          sev = normalize_severity(line)
          rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), sev, tidy(line), File.basename(file)]

          record_stat(:errors_found) if sev == 'ERROR'
          record_stat(:warnings_found) if sev == 'WARN'
        end
      end

      record_stat(:lines_processed, line_count)
      $logger.debug "    Found #{matched_lines}/#{line_count} lines in time window" if verbose && matched_lines > 0

    rescue => e
      $logger.error "Failed to read #{file}: #{e.message}"
      record_stat(:processing_errors)
      next
    end
  end

  CSV.open(csv_file, 'w', encoding: 'utf-8') { |csv| rows.each { |r| csv << r } }
  record_stat(:files_processed, files_processed)

  $summary_logger.info "#{name}: processed #{files_processed}/#{files_found} files, #{rows.length - 1} log lines collected"
end

def include_existing_csv(path, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(path)

  FileUtils.mkdir_p(dest_folder)
  dest = File.join(dest_folder, File.basename(path))
  $logger.info "Including provided CSV: #{path}"

  rows_collected = 0

  begin
    CSV.open(dest, 'w', encoding: 'utf-8') do |csv|
      csv << ['timestamp','severity','log_line','source']

      CSV.foreach(path, headers: true, skip_blanks: true) do |row|
        raw_line = (row['log_line'] || row.to_s)
        parsed_ts = parse_timestamp_from_line(raw_line) || (row['timestamp'] ? (begin; Time.parse(row['timestamp']) rescue nil end) : nil)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        rows_collected += 1
        sev = normalize_severity(raw_line, row['severity'])
        csv << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), sev, tidy(raw_line), File.basename(path)]
      end
    end

  rescue CSV::MalformedCSVError => e
    $logger.warn "Malformed CSV #{path}: #{e.message}, attempting line-by-line read"

    CSV.open(dest, 'w', encoding: 'utf-8') do |csv|
      csv << ['timestamp','severity','log_line','source']
      File.foreach(path, encoding: 'bom|utf-8') do |line|
        next if line.strip.empty?
        parsed_ts = parse_timestamp_from_line(line)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        rows_collected += 1
        csv << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), normalize_severity(line), tidy(line), File.basename(path)]
      end
    end

  rescue => e
    $logger.error "Failed to include CSV #{path}: #{e.message}"
    record_stat(:processing_errors)
  end

  $summary_logger.info "Custom CSV: collected #{rows_collected} rows from #{File.basename(path)}"
end

def extract_errors(csv_file, keywords, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(csv_file)

  $logger.debug "Filtering errors in #{File.basename(csv_file)}" if verbose

  pat = Regexp.new(keywords.join('|'), Regexp::IGNORECASE)
  out_rows = [['timestamp','severity','log_line','source']]

  begin
    CSV.foreach(csv_file, headers: true, skip_blanks: true) do |row|
      begin
        log_line = row['log_line'] || row.to_s
        next if log_line.nil? || log_line.strip.empty?

        parsed_ts = parse_timestamp_from_line(log_line) || (row['timestamp'] ? (begin; Time.parse(row['timestamp']) rescue nil end) : nil)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        if log_line =~ pat
          sev = normalize_severity(log_line, row['severity'])
          out_rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), 'ALERT', tidy(log_line, 2000), File.basename(csv_file)]
          record_stat(:alerts_extracted)
        end
      rescue => row_error
        $logger.debug "Error processing row in #{csv_file}: #{row_error.message}" if verbose
        next
      end
    end
  rescue => e
    $logger.error "Failed to extract from #{csv_file}: #{e.message}"
    record_stat(:processing_errors)
  end

  unless out_rows.length == 1
    out_csv = File.join(dest_folder, "alerts_#{File.basename(csv_file)}")
    CSV.open(out_csv, 'w', encoding: 'utf-8') { |csv| out_rows.each { |r| csv << r } }
    $logger.info "  Extracted #{out_rows.length - 1} alerts to #{File.basename(out_csv)}"
  end
end

def readable_from_csv(csv_path, out_path, opts = {})
  timestamp_fields = opts[:timestamp_fields] || ['TimeCreated','timestamp','time']
  id_fields = opts[:id_fields] || ['Id','EventID','Event']
  level_fields = opts[:level_fields] || ['LevelDisplayName','Level','Severity']
  source_fields = opts[:source_fields] || ['ProviderName','source','Source']
  message_fields = opts[:message_fields] || ['Message','MessageText','log_line','log']

  File.open(out_path, 'w', encoding: 'utf-8') do |out|
    begin
      CSV.foreach(csv_path, headers: true, skip_blanks: true) do |row|
        ts = nil
        timestamp_fields.each { |f| ts = row[f] if ts.nil? && row && row.headers.include?(f) && row[f] }
        ts ||= row[0] rescue nil
        ts_readable = begin
          ts ? Time.parse(ts.to_s).strftime('%Y-%m-%d %H:%M:%S') : ''
        rescue
          ts.to_s
        end

        level = ''
        level_fields.each { |f| level = row[f].to_s if level.empty? && row && row.headers.include?(f) && row[f] }
        evt_id = ''
        id_fields.each { |f| evt_id = row[f].to_s if evt_id.empty? && row && row.headers.include?(f) && row[f] }
        src = ''
        source_fields.each { |f| src = row[f].to_s if src.empty? && row && row.headers.include?(f) && row[f] }
        msg = ''
        message_fields.each { |f| msg = row[f].to_s if msg.empty? && row && row.headers.include?(f) && row[f] }

        level = level.empty? ? (row['severity'] || 'INFO') : level
        src = src.empty? ? File.basename(csv_path) : src
        msg = tidy(msg)

        evt_part = (evt_id && evt_id.length > 0) ? " (EventID: #{evt_id})" : ''
        out.puts "[#{ts_readable}] #{level.ljust(7)} | #{tidy(src,80)} | #{msg}#{evt_part}"
      end
    rescue CSV::MalformedCSVError, ArgumentError => e
      File.readlines(csv_path, encoding: 'bom|utf-8').each_with_index do |line, idx|
        next if idx == 0 && line =~ /timestamp|TimeCreated/i
        line_s = tidy(line)
        next if line_s.empty?
        out.puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] INFO    | #{File.basename(csv_path)} | #{line_s}"
      end
    rescue => ex
      out.puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] ERROR   | Failed to parse #{csv_path}: #{ex}"
    end
  end
end

def build_readable_reports(rootdir, readable_folder, verbose: false)
  $logger.info "Building readable reports"

  csv_files = Dir.glob("#{rootdir}/**/*.csv").select { |p| File.file?(p) }
  csv_files.each do |csvfile|
    next if File.basename(csvfile).start_with?('alerts_')
    folder = File.dirname(csvfile)
    base = File.basename(csvfile, '.csv')
    outpth = File.join(readable_folder, "readable_#{base}.txt")

    if folder =~ /WindowsEvent/i
      readable_from_csv(csvfile, outpth, {
        timestamp_fields: ['TimeCreated']
      })
    else
      readable_from_csv(csvfile, outpth)
    end

    $logger.debug "  Created readable report: #{File.basename(outpth)}" if verbose
  end
end

def system_snapshot(root, verbose: false)
  out = File.join(root, 'SystemSnapshot')
  FileUtils.mkdir_p(out)
  $logger.info "Capturing system snapshot"

  ps = <<-PS
Get-CimInstance Win32_LogicalDisk | Export-Csv '#{out}/Disk.csv' -NoTypeInformation -Encoding utf8
Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory | Export-Csv '#{out}/Memory.csv' -NoTypeInformation -Encoding utf8
Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1 -MaxSamples 5 | Export-Csv '#{out}/CPU.csv' -NoTypeInformation -Encoding utf8
PS

  run_powershell(ps, verbose: verbose)
end

def generate_collection_summary
  elapsed = Time.now - $stats[:start_time]

  summary = <<~SUMMARY
    ================================================================================
    Incident Collection Summary
    ================================================================================
    Collection Time: #{incident_time.strftime('%Y-%m-%d %H:%M:%S')}
    Time Window: #{start_time.strftime('%Y-%m-%d %H:%M:%S')} to #{end_time.strftime('%Y-%m-%d %H:%M:%S')}
    Duration: #{sprintf('%.2f', elapsed)} seconds

    Statistics:
    - Files Processed: #{$stats[:files_processed]}
    - Lines Processed: #{$stats[:lines_processed]}
    - Errors Found: #{$stats[:errors_found]}
    - Warnings Found: #{$stats[:warnings_found]}
    - Alerts Extracted: #{$stats[:alerts_extracted]}
    - Processing Errors: #{$stats[:processing_errors]}

    Output Location: #{ROOTDIR}
    ================================================================================
  SUMMARY

  File.write(File.join(ROOTDIR, 'SUMMARY.txt'), summary)
  $summary_logger.info summary
  puts summary
end

# -----------------------------
# Main execution
# -----------------------------
puts "\n==== Incident Collection Started ===="
puts "Time window: #{start_time.strftime('%Y-%m-%d %H:%M:%S %Z')} to #{end_time.strftime('%Y-%m-%d %H:%M:%S %Z')}"
puts "Output: #{ROOTDIR}\n\n"

$summary_logger.info "=" * 80
$summary_logger.info "Incident Collection Started at #{incident_time}"
$summary_logger.info "Time Window: #{start_time} to #{end_time}"
$summary_logger.info "=" * 80

begin
  # Windows event logs
  unless options[:skip_windows]
    %w[System Application Security].each do |log|
      collect_windows_events(log, ((end_time - start_time) / 3600.0).ceil, FOLDERS[:windows], verbose: options[:verbose])
    end
  end

  # File-based logs
  collect_logs_from_dir('PostgreSQL', LOG_PATHS[:postgresql], start_time, end_time, FOLDERS[:postgresql],
                        all_files: options[:all_files], verbose: options[:verbose])

  collect_logs_from_dir('Datadog', LOG_PATHS[:datadog], start_time, end_time, FOLDERS[:datadog],
                        all_files: options[:all_files], verbose: options[:verbose])

  collect_logs_from_dir('IMQS', LOG_PATHS[:imqs], start_time, end_time, FOLDERS[:imqs],
                        all_files: options[:all_files], verbose: options[:verbose])

  # Include custom CSV if specified
  if options[:sample_csv] && File.exist?(options[:sample_csv])
    include_existing_csv(options[:sample_csv], FOLDERS[:datadog], start_time, end_time, verbose: options[:verbose])
  elsif File.exist?(SAMPLE_DATADOG_CSV)
    include_existing_csv(SAMPLE_DATADOG_CSV, FOLDERS[:datadog], start_time, end_time, verbose: options[:verbose])
  end

  # Extraction pass
  $logger.info "Extracting alerts with keywords: #{KEYWORDS.join(', ')}"
  Dir.glob("#{ROOTDIR}/**/*.csv").each do |csv|
    extract_errors(csv, KEYWORDS, FOLDERS[:extracted], start_time, end_time, verbose: options[:verbose])
  end

  # Build readable reports
  build_readable_reports(ROOTDIR, FOLDERS[:readable], verbose: options[:verbose])

  # System snapshot
  system_snapshot(ROOTDIR, verbose: options[:verbose]) unless options[:skip_snapshot]

  # Generate summary
  generate_collection_summary

  puts "\n Incident collection completed successfully!"
  puts "Package location: #{ROOTDIR}"
  puts "Summary log: #{SUMMARY_LOG}"

rescue => e
  $logger.error "Fatal error during collection: #{e.message}"
  $logger.error e.backtrace.join("\n")
  $summary_logger.error "Collection failed: #{e.message}"
  exit(1)
end