#!/usr/bin/env ruby
# TripWire - Enhanced Incident Detection and Collection System
# Automated log collection and analysis tool for incident response
#
# Version: 2.1 - Robust Edition
# Ruby Compatibility: 2.5+
# Description: Collects, filters, and analyzes system logs to detect incidents
#              across Windows Events, PostgreSQL, Datadog, and IMQS systems.

require 'fileutils'
require 'time'
require 'optparse'
require 'tempfile'
require 'logger'
require 'date'

# Graceful exit handler
trap('INT') do
  puts "\n\n  TripWire interrupted by user. Cleaning up..."
  exit(130)
end

def print_banner(version)
  width = 74
  title = "Incident Detection & Collection System"
  version_line = "Version #{version}"
  centered_title = title.center(width)
  centered_version = version_line.center(width)

  puts <<~BANNER

    ╔#{'═' * width}╗
    ║#{' ' * width}║
    ║   ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗              ║
    ║   ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝              ║
    ║      ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗                ║
    ║      ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝                ║
    ║      ██║   ██║  ██║██║██║     ╚███╔███╔╝██║██║  ██║███████╗              ║
    ║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝              ║
    ║#{centered_title}║
    ║#{centered_version}║
    ║#{' ' * width}║
    ╚#{'═' * width}╝

  BANNER
end

TRIPWIRE_VERSION = "2.1-Robust"

print_banner(TRIPWIRE_VERSION)

# =============================================================================
# TSV MODULE - All TSV operations with robust error handling
# =============================================================================

module TSV
  class << self
    def write(file, rows)
      return false if rows.nil? || rows.empty?
      
      File.open(file, 'w:UTF-8') do |f|
        rows.each do |row| 
          next if row.nil?
          f.puts sanitize_row(row).join("\t")
        end
      end
      true
    rescue => e
      warn "TSV write failed (#{file}): #{e.message}"
      false
    end

    def read(file, headers: true)
      return [] unless File.exist?(file)
      
      lines = File.readlines(file, encoding: 'bom|utf-8').map(&:strip).reject(&:empty?)
      return [] if lines.empty?
      
      if headers
        header_row = lines[0].split("\t")
        lines[1..-1].map do |line| 
          values = line.strip.split("\t", -1)  # -1 to keep trailing empty fields
          Hash[header_row.zip(values)]
        end
      else
        lines.map { |line| line.split("\t", -1) }
      end
    rescue => e
      warn "TSV read failed (#{file}): #{e.message}"
      []
    end

    def foreach(file, headers: true)
      return unless File.exist?(file) && block_given?
      
      File.open(file, 'r:bom|utf-8') do |f|
        header_row = headers ? f.readline.strip.split("\t", -1) : nil
        
        f.each_line do |line|
          next if line.strip.empty?
          values = line.strip.split("\t", -1)
          
          begin
            yield(headers ? Hash[header_row.zip(values)] : values)
          rescue => e
            # Continue processing even if one row fails
            warn "Skipped malformed row: #{e.message}" if $VERBOSE
          end
        end
      end
    rescue => e
      warn "TSV foreach failed (#{file}): #{e.message}"
    end

    def append(file, rows)
      return false if rows.nil? || rows.empty?
      
      File.open(file, 'a:UTF-8') do |f|
        rows.each do |row|
          next if row.nil?
          f.puts sanitize_row(row).join("\t")
        end
      end
      true
    rescue => e
      warn "TSV append failed (#{file}): #{e.message}"
      false
    end

    private

    def sanitize_row(row)
      return [] if row.nil?
      row.map { |cell| sanitize_cell(cell) }
    end

    def sanitize_cell(value)
      return '' if value.nil?
      # Remove tabs, newlines, carriage returns
      value.to_s.gsub(/[\t\r\n]+/, ' ').strip
    end
  end
end

# -----------------------------
# TripWire Configuration
# -----------------------------
DEFAULT_HOURS = 24
KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
ROOT_BASE = Dir.pwd

LOG_PATHS = {
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
  datadog: 'C:/ProgramData/Datadog/logs'
}

# Security log optimization: Define which Event IDs to collect
SECURITY_EVENT_IDS = [
  4625,  # Failed login
  4648,  # Logon using explicit credentials  
  4672,  # Special privileges assigned to new logon
  4720,  # User account created
  4722,  # User account enabled
  4724,  # Password reset attempt
  4732,  # Member added to security-enabled local group
  4735,  # Security-enabled local group changed
  4738,  # User account changed
  4740,  # User account locked out
  4756,  # Member added to security-enabled universal group
  1102   # Audit log cleared
]

# For System/Application logs: collect only errors and warnings?
ERRORS_WARNINGS_ONLY = true

# -----------------------------
# Logging setup
# -----------------------------
$logger = Logger.new(STDOUT)
$logger.level = Logger::INFO
$logger.formatter = proc do |severity, datetime, progname, msg|
  "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] [TripWire] #{severity.ljust(5)} | #{msg}\n"
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
  sample_tsv: nil,
  skip_windows: false,
  skip_snapshot: false,
  config_file: nil,
  all_security_events: false,
  all_event_levels: false,
  parallel: false,
  security_ids: nil,
  debug_tsv: false
}

OptionParser.new do |opts|
  opts.banner = <<~BANNER
    ═══════════════════════════════════════════════════════════════════════════
    TripWire v#{TRIPWIRE_VERSION} - Incident Detection & Collection System
    ═══════════════════════════════════════════════════════════════════════════
    
    Usage: ruby TripWire.rb [options]
  BANNER

  opts.on("--last DURATION", "Collect logs from the last duration (e.g., 6h, 2d, 1w)") do |dur|
    options[:mode] = :last
    options[:last_raw] = dur
  end

  opts.on("--back SPEC", "Collect logs from a past date offset (e.g., 2m1w3d)") do |raw|
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

  opts.on("--verbose", "Enable verbose output for debugging") do
    options[:verbose] = true
    $logger.level = Logger::DEBUG
  end

  opts.on("--skip-windows", "Skip Windows Event Log collection") do
    options[:skip_windows] = true
  end

  opts.on("--skip-snapshot", "Skip system snapshot collection") do
    options[:skip_snapshot] = true
  end

  opts.on("--all-security-events", "Collect ALL Security log events (much slower)") do
    options[:all_security_events] = true
  end

  opts.on("--all-event-levels", "Collect all event levels, not just errors/warnings") do
    options[:all_event_levels] = true
  end

  opts.on("--parallel", "Collect Windows logs in parallel (faster, more CPU)") do
    options[:parallel] = true
  end

  opts.on("--security-ids IDS", "Comma-separated Event IDs for Security log") do |ids|
    options[:security_ids] = ids.split(',').map(&:strip).map(&:to_i)
  end

  opts.on("--debug-tsv", "Show TSV file contents for debugging") do
    options[:debug_tsv] = true
  end

  opts.on("--sample-tsv PATH", "Include a specific TSV file in collection") do |path|
    options[:sample_tsv] = path
  end

  opts.on("--config FILE", "Load custom log paths from config file") do |file|
    options[:config_file] = file
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    puts "\n" + "─" * 79
    puts "Examples:"
    puts "  ruby TripWire.rb --last 6h"
    puts "  ruby TripWire.rb --yesterday --verbose"
    puts "  ruby TripWire.rb --back 2m1w3d"
    puts "  ruby TripWire.rb --today --skip-windows"
    puts "  ruby TripWire.rb --last 6h --parallel"
    puts "  ruby TripWire.rb --all-security-events"
    puts "  ruby TripWire.rb --security-ids 4625,4720"
    puts "─" * 79
    exit
  end

  opts.on("--version", "Show TripWire version") do
    puts "TripWire v#{TRIPWIRE_VERSION}"
    exit
  end
end.parse!

# -----------------------------
# Load custom config if provided
# -----------------------------
if options[:config_file] && File.exist?(options[:config_file])
  begin
    eval(File.read(options[:config_file]))
    $logger.info "Configuration loaded from #{options[:config_file]}"
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
  unless back_raw =~ /\A(?:\d+[mwd])+\z/i
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
  if raw =~ /\A(\d+)([hdw])\z/i
    amount, unit = Regexp.last_match(1).to_i, Regexp.last_match(2).downcase
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
# Setup TripWire output structure
# -----------------------------
incident_time = Time.now
ROOTDIR = File.join(ROOT_BASE, "TripWire_#{incident_time.strftime('%Y%m%d-%H%M%S')}")

begin
  FileUtils.mkdir_p(ROOTDIR)
rescue => e
  $logger.fatal "Cannot create output directory: #{e.message}"
  exit(1)
end

FOLDERS = {
  windows: File.join(ROOTDIR, 'WindowsEvent'),
  datadog: File.join(ROOTDIR, 'Datadog'),
  postgresql: File.join(ROOTDIR, 'PostgreSQL'),
  extracted: File.join(ROOTDIR, 'ExtractedAlerts'),
  readable: File.join(ROOTDIR, 'ReadableReports'),
  snapshots: File.join(ROOTDIR, 'SystemSnapshot')
}

FOLDERS.each_value do |path|
  begin
    FileUtils.mkdir_p(path)
  rescue => e
    $logger.error "Failed to create folder #{path}: #{e.message}"
  end
end

# Create TripWire summary log
SUMMARY_LOG = File.join(ROOTDIR, 'TripWire_Summary.log')
begin
  $summary_logger = Logger.new(SUMMARY_LOG)
  $summary_logger.formatter = proc { |severity, datetime, progname, msg| "#{msg}\n" }
rescue => e
  $logger.warn "Could not create summary log: #{e.message}"
  $summary_logger = Logger.new(STDOUT)
end

# -----------------------------
# TripWire Statistics Tracker
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
def progress_bar(current, total, prefix: '', bar_length: 40)
  return if total.to_i <= 0
  
  begin
    percent = (current.to_f / total * 100).round(1)
    filled = (bar_length * current / total.to_f).round
    filled = [filled, bar_length].min  # Ensure it doesn't exceed bar length
    bar = '█' * filled + '░' * (bar_length - filled)
    print "\r#{prefix.ljust(20)} [#{bar}] #{percent}% (#{current}/#{total})"
    puts if current >= total
  rescue => e
    # Silent failure - progress bar is cosmetic
  end
end

class Spinner
  FRAMES = ['|', '/', '-', '\\'].freeze

  def initialize(message)
    @message = message
    @running = false
    @frame = 0
    @thread = nil
  end

  def start
    @running = true
    @thread = Thread.new do
      begin
        while @running
          print "\r#{FRAMES[@frame]} #{@message}..."
          @frame = (@frame + 1) % FRAMES.length
          sleep 0.1
        end
      rescue => e
        # Silent failure
      end
    end
    self
  end

  def stop(final_message = nil)
    @running = false
    @thread.join if @thread
    print "\r#{' ' * (@message.length + 10)}\r"
    puts "✓ #{final_message}" if final_message
  rescue => e
    # Silent failure
  end
end

TIMESTAMP_PATTERNS = [
  /(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)/,
  /(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: \+\d{4})?(?: UTC)?/,
  /(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
  /(?<ts>\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2})/,
  /^\s*(?:INFO|WARN|ERROR|DEBUG|TRACE)\s+(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [+\-]\d{4})?)/x
].freeze

def parse_timestamp_from_line(line)
  return nil if line.nil? || line.empty?
  
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
rescue => e
  nil
end

def normalize_severity(line, explicit_severity = nil)
  return explicit_severity.upcase if explicit_severity && !explicit_severity.to_s.strip.empty?
  return 'INFO' if line.nil? || line.empty?
  
  if line =~ /^\s*(INFO|WARN|ERROR|DEBUG|TRACE)\b/i
    return Regexp.last_match(1).upcase
  end
  
  case line
  when /\b(ERROR|ERR|FATAL|SEVERE|CRITICAL)\b/i then 'ERROR'
  when /\b(WARN|WARNING)\b/i then 'WARN'
  when /\b(INFO|INFORMATION)\b/i then 'INFO'
  when /\b(DEBUG|TRACE)\b/i then 'DEBUG'
  else 'INFO'
  end
rescue => e
  'INFO'
end

def tidy(msg, max_len = 1000)
  return '' if msg.nil?
  
  begin
    s = msg.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
    s = s.gsub(/\r?\n/, ' ').strip
    s.length > max_len ? (s[0...max_len] + '...') : s
  rescue => e
    msg.to_s[0...max_len] rescue ''
  end
end

def run_powershell(script, verbose: false)
  tf = nil
  begin
    tf = Tempfile.new(['psscript', '.ps1'])
    tf.write(script)
    tf.close
    
    ps_exe = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    cmd = "\"#{ps_exe}\" -NoProfile -ExecutionPolicy Bypass -File \"#{tf.path}\""
    
    $logger.debug "[PowerShell] Executing script: #{tf.path}" if verbose
    success = system(cmd)
    
    unless success
      $logger.error "PowerShell execution failed (exit code: #{$?.exitstatus rescue 'unknown'})"
      record_stat(:processing_errors)
    end
    
    success
  rescue => e
    $logger.error "PowerShell error: #{e.message}"
    record_stat(:processing_errors)
    false
  ensure
    if tf && tf.path && File.exist?(tf.path)
      begin
        tf.unlink
      rescue => e
        # Ignore cleanup errors
      end
    end
  end
end

# -----------------------------
# TripWire Collection Functions
# -----------------------------
def collect_windows_events(log, start_time, end_time, root, verbose: false, filter_ids: nil)
  out_dir = File.join(root, log)
  FileUtils.mkdir_p(out_dir)
  tsv_file = File.join(out_dir, "#{log}_events.tsv")

  $logger.info "🔍 Scanning Windows #{log} events"

  ps_start = start_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
  ps_end   = end_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

  filter_parts = ["LogName='#{log}'", "StartTime=$start", "EndTime=$end"]
  
  # Apply filters
  if filter_ids && !filter_ids.empty?
    filter_parts << "ID=#{filter_ids.join(',')}"
    $logger.info "   (Filtering to #{filter_ids.size} specific event IDs)"
  elsif log == 'Security' && defined?(SECURITY_EVENT_IDS) && SECURITY_EVENT_IDS && !options[:all_security_events]
    filter_parts << "ID=#{SECURITY_EVENT_IDS.join(',')}"
    $logger.info "   (Filtering Security log to #{SECURITY_EVENT_IDS.size} critical event types)"
  end
  
  if log != 'Security' && defined?(ERRORS_WARNINGS_ONLY) && ERRORS_WARNINGS_ONLY
    filter_parts << "Level=1,2,3"
    $logger.info "   (Filtering to errors and warnings only)"
  end

  filter_hash = filter_parts.join('; ')

  ps = <<~PS
    $start = [datetime]'#{ps_start}'
    $end   = [datetime]'#{ps_end}'
    $filter = @{#{filter_hash}}
    
    try {
      $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 10000 -ErrorAction Stop |
        Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
      
      if ($events -and $events.Count -gt 0) {
        $events | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
          Out-File -FilePath '#{tsv_file}' -Encoding utf8 -Force
        Write-Host "Collected $($events.Count) events"
      } else {
        "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" |
          Out-File -FilePath '#{tsv_file}' -Encoding utf8 -Force
        Write-Host "No events found in time range"
      }
    } catch {
      "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" |
        Out-File -FilePath '#{tsv_file}' -Encoding utf8 -Force
      Write-Host "Error: $_"
    }
  PS

  spinner = Spinner.new("Reading Windows #{log} events")
  spinner.start unless verbose

  success = run_powershell(ps, verbose: verbose)

  spinner.stop unless verbose

  if File.exist?(tsv_file)
    record_stat(:files_processed)
    begin
      line_count = File.readlines(tsv_file, encoding: 'bom|utf-8').count - 1
      line_count = [line_count, 0].max
      record_stat(:lines_processed, line_count)
      $summary_logger.info "✓ Windows #{log}: #{line_count} events collected"
      $logger.info "   ✓ Collected #{line_count} #{log} events"
    rescue => e
      $logger.warn "Could not count lines in #{tsv_file}: #{e.message}"
    end
  else
    $logger.warn "⚠  Expected TSV not found: #{tsv_file}"
    record_stat(:processing_errors)
  end
rescue => e
  $logger.error "Failed to collect Windows #{log} events: #{e.message}"
  record_stat(:processing_errors)
end

def collect_logs_from_dir(name, path, start_time, end_time, root, all_files: false, verbose: false)
  out_dir = File.join(root, name)
  FileUtils.mkdir_p(out_dir)
  tsv_file = File.join(out_dir, "#{name}.tsv")

  $logger.info "🔍 Scanning #{name} logs (#{path})"

  unless Dir.exist?(path)
    TSV.write(tsv_file, [['timestamp','severity','log_line','source']])
    $logger.warn "  ⚠  Directory not found, skipping"
    $summary_logger.info "✗ #{name}: directory not found"
    return
  end

  rows = [['timestamp','severity','log_line','source']]
  files_found = 0
  files_processed = 0

  begin
    files = Dir.glob(File.join(path, '*')).sort
  rescue => e
    $logger.error "Failed to list files in #{path}: #{e.message}"
    TSV.write(tsv_file, rows)
    return
  end

  files.each do |file|
    next unless File.file?(file)
    files_found += 1

    unless all_files
      begin
        mtime = File.mtime(file)
        next if mtime < start_time || mtime > end_time
      rescue => e
        $logger.debug "Skipping #{file}: #{e.message}" if verbose
        next
      end
    end

    $logger.debug "   Processing: #{File.basename(file)}" if verbose
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
      $logger.debug "    ✓ Found #{matched_lines}/#{line_count} lines in time window" if verbose && matched_lines > 0

    rescue => e
      $logger.error "  ✗ Failed to read #{file}: #{e.message}"
      record_stat(:processing_errors)
      next
    end
  end

  TSV.write(tsv_file, rows)
  record_stat(:files_processed, files_processed)

  $summary_logger.info "✓ #{name}: #{files_processed}/#{files_found} files processed, #{rows.length - 1} log lines collected"
  $logger.info "  ✓ Processed #{files_processed}/#{files_found} files, #{rows.length - 1} lines"
rescue => e
  $logger.error "Error in collect_logs_from_dir for #{name}: #{e.message}"
  record_stat(:processing_errors)
end

def include_existing_tsv(path, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(path)

  FileUtils.mkdir_p(dest_folder)
  dest = File.join(dest_folder, File.basename(path))
  $logger.info " Including external TSV: #{File.basename(path)}"

  rows_collected = 0

  begin
    output_rows = [['timestamp','severity','log_line','source']]

    TSV.foreach(path) do |row|
      next if row.nil?
      
      raw_line = row['log_line'] || row['Message'] || row.values.join(' ')
      next if raw_line.to_s.strip.empty?
      
      parsed_ts = parse_timestamp_from_line(raw_line)
      parsed_ts ||= begin
        Time.parse(row['timestamp']) if row['timestamp']
      rescue
        nil
      end
      used_ts = parsed_ts || Time.now
      
      next if used_ts < start_time || used_ts > end_time

      rows_collected += 1
      sev = normalize_severity(raw_line, row['severity'])
      output_rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), sev, tidy(raw_line), File.basename(path)]
    end

    TSV.write(dest, output_rows)

  rescue => e
    $logger.error "  ✗ Failed to include TSV: #{e.message}"
    record_stat(:processing_errors)
  end
end

def include_existing_tsv(path, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(path)

  FileUtils.mkdir_p(dest_folder)
  dest = File.join(dest_folder, File.basename(path))
  $logger.info " Including external TSV: #{File.basename(path)}"

  rows_collected = 0

  begin
    output_rows = [['timestamp','severity','log_line','source']]

    TSV.foreach(path) do |row|
      next if row.nil?
      raw_line = row['log_line'] || row['Message'] || row.values.join(' ')
      parsed_ts = parse_timestamp_from_line(raw_line) || (row['timestamp'] ? (begin; Time.parse(row['timestamp']) rescue nil end) : nil)
      used_ts = parsed_ts || Time.now
      next if used_ts < start_time || used_ts > end_time

      rows_collected += 1
      sev = normalize_severity(raw_line, row['severity'])
      output_rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), sev, tidy(raw_line), File.basename(path)]
    end

    TSV.write(dest, output_rows)

  rescue => e
    $logger.error " Failed to include TSV: #{e.message}"
    record_stat(:processing_errors)
  end

  $summary_logger.info " External TSV: #{rows_collected} rows from #{File.basename(path)}"
  $logger.info " Collected #{rows_collected} rows"
end

def extract_errors(tsv_file, keywords, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(tsv_file)

  $logger.debug " Filtering errors in #{File.basename(tsv_file)}" if verbose
  pat = Regexp.union(keywords.map { |k| /\b#{Regexp.escape(k)}\b/i })
  out_rows = [['timestamp','severity','log_line','source']]
  processed_lines = 0

  begin
    total_lines = TSV.read(tsv_file).size

    TSV.foreach(tsv_file) do |row|
      begin
        log_line = row['log_line'] || row['Message'] || row.values.join(' ')
        next if log_line.nil? || log_line.strip.empty?

        parsed_ts = parse_timestamp_from_line(log_line) || 
                    (Time.parse(row['TimeCreated']) rescue nil) ||
                    (Time.parse(row['timestamp']) rescue nil)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        if log_line.match?(pat)
          out_rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), 'ALERT', tidy(log_line, 2000), File.basename(tsv_file)]
          record_stat(:alerts_extracted)
        end

      rescue => row_error
        $logger.debug "Skipped malformed row in #{tsv_file}: #{row_error.message}" if verbose
        record_stat(:processing_errors)
      ensure
        processed_lines += 1
        progress_bar(processed_lines, total_lines, prefix: "Filtering #{File.basename(tsv_file)}") if total_lines > 0
      end
    end

  rescue => e
    $logger.error "Error processing #{tsv_file}: #{e.message}"
    record_stat(:processing_errors)
  end

  unless out_rows.length == 1
    FileUtils.mkdir_p(dest_folder)
    out_tsv = File.join(dest_folder, "alerts_#{File.basename(tsv_file)}")
    TSV.write(out_tsv, out_rows)
    $logger.info " Extracted #{out_rows.length - 1} alerts → #{File.basename(out_tsv)}"
  end
end

def readable_from_tsv(tsv_path, out_path)
  File.open(out_path, 'w', encoding: 'utf-8') do |out|
    out.puts "=" * 80
    out.puts "TripWire Readable Report"
    out.puts "Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
    out.puts "Source: #{File.basename(tsv_path)}"
    out.puts "=" * 80
    out.puts

    begin
      rows_written = 0
      
      TSV.foreach(tsv_path) do |row|
        next if row.nil? || row.empty?
        
        # Try to extract timestamp from various fields
        ts = row['TimeCreated'] || row['timestamp'] || row['time']
        ts_readable = if ts && !ts.strip.empty?
                        begin
                          Time.parse(ts).strftime('%Y-%m-%d %H:%M:%S')
                        rescue
                          ts.to_s[0...19]
                        end
                      else
                        Time.now.strftime('%Y-%m-%d %H:%M:%S')
                      end

        # Extract level/severity
        level = row['LevelDisplayName'] || row['Level'] || row['severity'] || 'INFO'
        level = level.to_s.strip
        level = 'INFO' if level.empty?

        # Extract event ID if present
        evt_id = row['Id'] || row['EventID'] || row['Event'] || ''
        evt_id = evt_id.to_s.strip

        # Extract source
        src = row['ProviderName'] || row['source'] || row['Source'] || File.basename(tsv_path)
        src = src.to_s.strip
        src = File.basename(tsv_path) if src.empty?

        # Extract message - try multiple fields
        msg = row['Message'] || row['log_line'] || row['log'] || row.values.join(' ')
        msg = tidy(msg.to_s)

        # Skip completely empty rows
        next if msg.empty? && evt_id.empty?

        # Format the line
        evt_part = (evt_id && !evt_id.empty?) ? " [ID:#{evt_id}]" : ''
        source_part = tidy(src, 40).ljust(40)
        
        out.puts "[#{ts_readable}] #{level.ljust(8)} | #{source_part} | #{msg}#{evt_part}"
        rows_written += 1
      end

      # If no rows were written, add a note
      if rows_written == 0
        out.puts "No events found in this log file."
        out.puts "(File may be empty or contain only headers)"
      else
        out.puts
        out.puts "=" * 80
        out.puts "Total events: #{rows_written}"
      end

    rescue => ex
      out.puts
      out.puts "ERROR: Failed to parse #{File.basename(tsv_path)}"
      out.puts "Reason: #{ex.message}"
      out.puts
      out.puts "Raw content dump:"
      out.puts "-" * 80
      
      # Fallback: dump raw lines
      begin
        File.readlines(tsv_path, encoding: 'bom|utf-8').each_with_index do |line, idx|
          next if idx == 0  # skip header
          line_s = line.strip
          next if line_s.empty?
          out.puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] RAW | #{tidy(line_s, 200)}"
        end
      rescue => dump_error
        out.puts "Could not dump raw content: #{dump_error.message}"
      end
    end
  end
  
  true
rescue => e
  $logger.error "Failed to create readable report for #{tsv_path}: #{e.message}"
  false
end

def build_readable_reports(root, dest_folder, verbose: false)
  # Get all TSVs but exclude the alerts folder (we'll report those separately)
  all_tsvs = Dir.glob(File.join(root, '**', '*.tsv')).reject { |f| f.include?('ExtractedAlerts') }
  
  return if all_tsvs.empty?
  
  FileUtils.mkdir_p(dest_folder)
  
  total_files = all_tsvs.size
  processed = 0
  reports_created = 0

  $logger.info "Generating #{total_files} readable reports..."

  all_tsvs.each do |tsv_file|
    processed += 1
    next unless File.exist?(tsv_file)

    # Check if TSV has data (more than just header)
    begin
      line_count = File.readlines(tsv_file, encoding: 'bom|utf-8').count
      if line_count <= 1
        $logger.debug "  Skipping empty TSV: #{File.basename(tsv_file)}" if verbose
        next
      end
    rescue
      next
    end

    progress_bar(processed, total_files, prefix: "Generating reports")

    begin
      report_file = File.join(dest_folder, "report_#{File.basename(tsv_file, '.tsv')}.txt")
      readable_from_tsv(tsv_file, report_file)
      reports_created += 1
      $logger.debug "  Created: #{File.basename(report_file)}" if verbose
    rescue => e
      $logger.error " Failed to generate report for #{tsv_file}: #{e.message}"
      record_stat(:processing_errors)
    end
  end
  
  $logger.info "  Generated #{reports_created} readable reports"
  
  # Also create reports for extracted alerts
  alert_tsvs = Dir.glob(File.join(root, 'ExtractedAlerts', '*.tsv'))
  if alert_tsvs.any?
    alert_tsvs.each do |alert_file|
      begin
        line_count = File.readlines(alert_file, encoding: 'bom|utf-8').count
        next if line_count <= 1
        
        report_file = File.join(dest_folder, "ALERTS_#{File.basename(alert_file, '.tsv')}.txt")
        readable_from_tsv(alert_file, report_file)
        $logger.info "  Created alert report: #{File.basename(report_file)}"
      rescue => e
        $logger.debug "  Failed to create alert report: #{e.message}" if verbose
      end
    end
  end
end

def system_snapshot(root, verbose: false)
  begin
    out = File.join(root, 'SystemSnapshot')
    FileUtils.mkdir_p(out)
    $logger.info " Capturing system snapshot"

    ps = <<~PS
      Get-CimInstance Win32_LogicalDisk |
        ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
        Out-File '#{out}/Disk.tsv' -Encoding utf8 -Force
      
      Get-CimInstance Win32_OperatingSystem |
        Select TotalVisibleMemorySize,FreePhysicalMemory |
        ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
        Out-File '#{out}/Memory.tsv' -Encoding utf8 -Force
      
      Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1 -MaxSamples 5 |
        ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
        Out-File '#{out}/CPU.tsv' -Encoding utf8 -Force
    PS

    spinner = Spinner.new("Capturing system snapshot (disk, memory, CPU)")
    spinner.start unless verbose

    success = run_powershell(ps, verbose: verbose)
    
    spinner.stop("System snapshot captured") unless verbose
    $logger.info "  ✓ Snapshot captured" if success && verbose

  end
end

def generate_tripwire_summary(incident_time, start_time, end_time, rootdir)
  elapsed = Time.now - $stats[:start_time]

  summary = <<~SUMMARY
    ═══════════════════════════════════════════════════════════════════════════
    TripWire v#{TRIPWIRE_VERSION} - Incident Collection Summary
    ═══════════════════════════════════════════════════════════════════════════
    
    Collection Started: #{incident_time.strftime('%Y-%m-%d %H:%M:%S')}
    Time Window: #{start_time.strftime('%Y-%m-%d %H:%M:%S')} → #{end_time.strftime('%Y-%m-%d %H:%M:%S')}
    Duration: #{sprintf('%.2f', elapsed)} seconds
    
    ─────────────────────────────────────────────────────────────────────────
    Detection Statistics
    ─────────────────────────────────────────────────────────────────────────
    Files Processed:     #{$stats[:files_processed].to_s.rjust(8)}
    Lines Analyzed:      #{$stats[:lines_processed].to_s.rjust(8)}
    Errors Detected:     #{$stats[:errors_found].to_s.rjust(8)}
    Warnings Detected:   #{$stats[:warnings_found].to_s.rjust(8)}
    Alerts Extracted:    #{$stats[:alerts_extracted].to_s.rjust(8)}
    Processing Errors:   #{$stats[:processing_errors].to_s.rjust(8)}
    
    ─────────────────────────────────────────────────────────────────────────
    Output Location
    ─────────────────────────────────────────────────────────────────────────
    #{rootdir}
    
    Key Files:
      • TripWire_Summary.log    - Detailed collection log
      • ExtractedAlerts/        - Critical incidents detected
      • ReadableReports/        - Human-readable format
      • SystemSnapshot/         - System state at collection time
    
    ═══════════════════════════════════════════════════════════════════════════
  SUMMARY

  File.write(File.join(rootdir, 'TripWire_Report.txt'), summary)
  $summary_logger.info summary
  puts "\n" + summary
end

# -----------------------------
# TripWire Main Execution
# -----------------------------
puts <<~BANNER
  TripWire v#{TRIPWIRE_VERSION}
  Collecting logs from #{start_time} to #{end_time}
BANNER

begin
  # 1) Windows Event logs - optionally run in parallel for speed
  unless options[:skip_windows]
    # Determine Security log filtering
    security_ids = if options[:security_ids]
                     options[:security_ids]  # Use CLI specified IDs
                   elsif options[:all_security_events]
                     nil  # No filtering
                   elsif defined?(SECURITY_EVENT_IDS)
                     SECURITY_EVENT_IDS  # Use config
                   else
                     nil
                   end
    
    
    if options[:parallel]
      $logger.info "Collecting Windows logs in parallel (3x faster)..."
      threads = []
      %w[System Application Security].each do |log|
        threads << Thread.new do
          Thread.current.abort_on_exception = true
          collect_windows_events(log, start_time, end_time, FOLDERS[:windows], verbose: options[:verbose])
        end
      end
      threads.each(&:join)
    else
      %w[System Application Security].each do |log|
        collect_windows_events(log, start_time, end_time, FOLDERS[:windows], verbose: options[:verbose])
      end
    end
  end

  # 2) Collect file-based logs (datadog/postgresql)
  collect_logs_from_dir('Datadog', LOG_PATHS[:datadog], start_time, end_time, FOLDERS[:datadog], all_files: options[:all_files], verbose: options[:verbose]) if LOG_PATHS[:datadog]
  collect_logs_from_dir('PostgreSQL', LOG_PATHS[:postgresql], start_time, end_time, FOLDERS[:postgresql], all_files: options[:all_files], verbose: options[:verbose]) if LOG_PATHS[:postgresql]

  # 3) Include sample TSV if provided
  include_existing_tsv(options[:sample_tsv], FOLDERS[:datadog], start_time, end_time, verbose: options[:verbose]) if options[:sample_tsv]

  # 4) Extract alerts from collected TSVs
  all_tsvs = Dir.glob(File.join(ROOTDIR, '**', '*.tsv'))
  all_tsvs.each do |tsvfile|
    extract_errors(tsvfile, KEYWORDS, FOLDERS[:extracted], start_time, end_time, verbose: options[:verbose])
  end

  # 5) Generate human readable reports
  $logger.info "Building readable reports..."
  
  # Debug: show TSV contents if requested
  if options[:debug_tsv]
    all_tsvs = Dir.glob(File.join(ROOTDIR, '**', '*.tsv'))
    all_tsvs.each do |tsv|
      puts "\n" + "="*80
      puts "DEBUG: #{tsv}"
      puts "="*80
      if File.exist?(tsv)
        lines = File.readlines(tsv, encoding: 'bom|utf-8')
        puts "Lines: #{lines.size}"
        puts "Header: #{lines[0].strip}" if lines[0]
        puts "First data row: #{lines[1].strip}" if lines[1]
        puts "Sample data:"
        lines[1..5].each_with_index do |line, idx|
          puts "  Row #{idx+1}: #{line.strip[0..100]}"
        end if lines.size > 1
      else
        puts "FILE NOT FOUND"
      end
    end
    puts "\n"
  end
  
  build_readable_reports(ROOTDIR, FOLDERS[:readable], verbose: options[:verbose])
  
  # Count generated reports
  report_count = Dir.glob(File.join(FOLDERS[:readable], '*.txt')).size
  $logger.info "  Total readable reports created: #{report_count}"

  # 6) Capture a system snapshot (unless skipped)
  system_snapshot(ROOTDIR, verbose: options[:verbose]) unless options[:skip_snapshot]

  # 7) Final summary
  generate_tripwire_summary(incident_time, start_time, end_time, ROOTDIR)

rescue => e
  $logger.fatal "Unhandled error: #{e.class}: #{e.message}\n#{e.backtrace.first(10).join("\n")}"
  record_stat(:processing_errors)
  generate_tripwire_summary(incident_time, start_time, end_time, ROOTDIR)
  exit(2)
end