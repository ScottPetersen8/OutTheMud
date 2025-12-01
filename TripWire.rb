#!/usr/bin/env ruby
# TripWire - Enhanced Incident Detection and Collection System
# Automated log collection and analysis tool for incident response
#
# Version: 2.0 
# Description: Collects, filters, and analyzes system logs to detect incidents
#              across Windows Events, PostgreSQL, Datadog, and IMQS systems.

require 'fileutils'
require 'time'
require 'csv'
require 'optparse'
require 'tempfile'
require 'logger'
require 'date'

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

TRIPWIRE_VERSION = "2.0"

print_banner(TRIPWIRE_VERSION)

# -----------------------------
# TripWire Configuration
# -----------------------------
DEFAULT_HOURS = 24
KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
ROOT_BASE = Dir.pwd
SAMPLE_DATADOG_CSV = '/mnt/data/Datadog.csv'

LOG_PATHS = {
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
  datadog: 'C:/ProgramData/Datadog/logs'
}

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
  sample_csv: nil,
  skip_windows: false,
  skip_snapshot: false,
  config_file: nil
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

  opts.on("--sample-csv PATH", "Include a specific CSV file in collection") do |path|
    options[:sample_csv] = path
  end

  opts.on("--config FILE", "Load custom log paths from config file") do |file|
    options[:config_file] = file
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    puts "\n" + "─" * 79
    puts "Examples:"
    puts "  ruby TripWire.rb --last 6h              # Last 6 hours"
    puts "  ruby TripWire.rb --yesterday --verbose  # Yesterday with details"
    puts "  ruby TripWire.rb --back 2m1w3d          # 2 months, 1 week, 3 days ago"
    puts "  ruby TripWire.rb --today --skip-windows # Today, skip Windows logs"
    puts "─" * 79
    puts "\nTripWire will detect and extract incidents from configured log sources."
    puts "Results are organized in timestamped folders with human-readable reports."
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
# Setup TripWire output structure
# -----------------------------
incident_time = Time.now
ROOTDIR = File.join(ROOT_BASE, "TripWire_#{incident_time.strftime('%Y%m%d-%H%M%S')}")
FileUtils.mkdir_p(ROOTDIR)

FOLDERS = {
  windows: File.join(ROOTDIR, 'WindowsEvent'),
  datadog: File.join(ROOTDIR, 'Datadog'),
  postgresql: File.join(ROOTDIR, 'PostgreSQL'),
  extracted: File.join(ROOTDIR, 'ExtractedAlerts'),
  readable: File.join(ROOTDIR, 'ReadableReports'),
  snapshots: File.join(ROOTDIR, 'SystemSnapshot')
}
FOLDERS.each_value { |p| FileUtils.mkdir_p(p) }

# Create TripWire summary log
SUMMARY_LOG = File.join(ROOTDIR, 'TripWire_Summary.log')
$summary_logger = Logger.new(SUMMARY_LOG)
$summary_logger.formatter = proc { |severity, datetime, progname, msg| "#{msg}\n" }

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
  percent = (current.to_f / total * 100).round(1)
  filled = (bar_length * current / total.to_f).round
  bar = '█' * filled + '░' * (bar_length - filled)
  print "\r#{prefix.ljust(20)} [#{bar}] #{percent}% (#{current}/#{total})"
  puts if current == total
end

class Spinner
  FRAMES = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏]

  def initialize(message)
    @message = message
    @running = false
    @frame = 0
  end

  def start
    @running = true
    @thread = Thread.new do
      while @running
        print "\r#{FRAMES[@frame]} #{@message}..."
        @frame = (@frame + 1) % FRAMES.length
        sleep 0.1
      end
    end
    self
  end

  def stop(final_message = nil)
    @running = false
    @thread.join if @thread

    # clear spinner line
    print "\r#{' ' * (@message.length + 10)}\r"

    if final_message
      puts "✓ #{final_message}"
    end
  end
end


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
  if csv_severity && !csv_severity.to_s.strip.empty?
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
  $logger.debug "[PowerShell] Executing script: #{tf.path}" if verbose
  success = system(cmd)
  unless success
    $logger.error "PowerShell execution failed (exit code: #{$?.exitstatus rescue 'unknown'})"
    record_stat(:processing_errors)
  end
  success
ensure
  tf.unlink if tf && tf.path && File.exist?(tf.path)
end

# -----------------------------
# TripWire Collection Functions
# -----------------------------
def collect_windows_events(log, start_time, end_time, root, verbose: false)
  out_dir = File.join(root, log)
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{log}_events.csv")

  $logger.info " Scanning Windows #{log} events (#{start_time} → #{end_time})"

  # build powershell time filters
  ps_start = start_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
  ps_end   = end_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

  ps = <<~PS
    $start = [datetime]'#{ps_start}'
    $end   = [datetime]'#{ps_end}'
    $filter = @{LogName='#{log}'; StartTime=$start; EndTime=$end}
    try {
      $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
        Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
      if ($events -and $events.Count -gt 0) {
        $events | Export-Csv -Path '#{csv_file}' -NoTypeInformation -Encoding utf8 -Force
      } else {
        "TimeCreated,Id,LevelDisplayName,ProviderName,Message" | Out-File -FilePath '#{csv_file}' -Encoding utf8
      }
    } catch {
      "TimeCreated,Id,LevelDisplayName,ProviderName,Message" | Out-File -FilePath '#{csv_file}' -Encoding utf8
    }
  PS

  # ---------------------------------------------------------------------
  #  ADD SPINNER WHILE POWERSHELL IS RUNNING (otherwise UI looks frozen)
  # ---------------------------------------------------------------------
  scanning = true
  spinner_chars = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏]
  spinner_index = 0

  spinner_thread = Thread.new do
    while scanning
      print "\r  #{spinner_chars[spinner_index]} Reading Windows #{log} events..."
      spinner_index = (spinner_index + 1) % spinner_chars.size
      sleep(0.1)
    end
  end
  # ---------------------------------------------------------------------

  # RUN POWERSHELL (this blocks for a long time)
  success = run_powershell(ps, verbose: verbose)

  # ---------------------------------------------------------------------
  # STOP SPINNER
  # ---------------------------------------------------------------------
  scanning = false
  spinner_thread.join
  print "\r" + (" " * 80) + "\r"   # clean line
  # ---------------------------------------------------------------------

  if File.exist?(csv_file)
    record_stat(:files_processed)

    line_count = 0
    begin
      line_count = File.readlines(csv_file, encoding: 'bom|utf-8').count - 1
      line_count = 0 if line_count < 0
    rescue
      line_count = 0
    end

    record_stat(:lines_processed, line_count)
    $summary_logger.info " Windows #{log}: #{line_count} events collected"
    $logger.info "   Collected #{line_count} #{log} events"
  else
    $logger.warn " Expected CSV not found: #{csv_file}"
    record_stat(:processing_errors)
  end
end

def collect_logs_from_dir(name, path, start_time, end_time, root, all_files: false, verbose: false)
  out_dir = File.join(root, name)
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{name}.csv")

  $logger.info " Scanning #{name} logs (#{path})"

  unless Dir.exist?(path)
    CSV.open(csv_file, 'w', encoding: 'utf-8') { |csv| csv << ['timestamp','severity','log_line','source'] }
    $logger.warn " Directory not found, skipping"
    $summary_logger.info " #{name}: directory not found"
    return
  end

  rows = [['timestamp','severity','log_line','source']]
  files_found = 0
  files_processed = 0

  Dir.glob(File.join(path, '*')).sort.each do |file|
    next unless File.file?(file)
    files_found += 1

    unless all_files
      mtime = File.mtime(file) rescue next
      next if mtime < start_time || mtime > end_time
    end

    $logger.debug " Processing: #{File.basename(file)}" if verbose
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
      $logger.debug "  Found #{matched_lines}/#{line_count} lines in time window" if verbose && matched_lines > 0

    rescue => e
      $logger.error "  Failed to read #{file}: #{e.message}"
      record_stat(:processing_errors)
      next
    end
  end

  CSV.open(csv_file, 'w', encoding: 'utf-8') { |csv| rows.each { |r| csv << r } }
  record_stat(:files_processed, files_processed)

  $summary_logger.info " #{name}: #{files_processed}/#{files_found} files processed, #{rows.length - 1} log lines collected"
  $logger.info "  Processed #{files_processed}/#{files_found} files, #{rows.length - 1} lines"
end

def include_existing_csv(path, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(path)

  FileUtils.mkdir_p(dest_folder)
  dest = File.join(dest_folder, File.basename(path))
  $logger.info " Including external CSV: #{File.basename(path)}"

  rows_collected = 0

  begin
    CSV.open(dest, 'w', encoding: 'utf-8') do |csv_out|
      csv_out << ['timestamp','severity','log_line','source']

      CSV.foreach(path, headers: true, encoding: 'bom|utf-8', skip_blanks: true) do |row|
        next if row.nil?
        # prefer explicit log_line header, otherwise join all fields into a single string
        raw_line = row['log_line'] || row['Message'] || row.to_hash.values.join(' ')
        parsed_ts = parse_timestamp_from_line(raw_line) || (row['timestamp'] ? (begin; Time.parse(row['timestamp']) rescue nil end) : nil)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        rows_collected += 1
        sev = normalize_severity(raw_line, row['severity'])
        csv_out << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), sev, tidy(raw_line), File.basename(path)]
      end
    end

  rescue CSV::MalformedCSVError => e
    $logger.warn "  Malformed CSV, attempting line-by-line read"

    CSV.open(dest, 'w', encoding: 'utf-8') do |csv_out|
      csv_out << ['timestamp','severity','log_line','source']
      File.foreach(path, encoding: 'bom|utf-8') do |line|
        next if line.strip.empty?
        parsed_ts = parse_timestamp_from_line(line)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        rows_collected += 1
        csv_out << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), normalize_severity(line), tidy(line), File.basename(path)]
      end
    end

  rescue => e
    $logger.error " Failed to include CSV: #{e.message}"
    record_stat(:processing_errors)
  end

  $summary_logger.info " External CSV: #{rows_collected} rows from #{File.basename(path)}"
  $logger.info " Collected #{rows_collected} rows"
end

def extract_errors(csv_file, keywords, dest_folder, start_time, end_time, verbose: false)
  return unless File.exist?(csv_file)

  $logger.debug " Filtering errors in #{File.basename(csv_file)}" if verbose
  pat = Regexp.union(keywords)
  out_rows = [['timestamp','severity','log_line','source']]
  processed_lines = 0

  begin
    total_lines = CSV.read(csv_file, headers: true, encoding: 'bom|utf-8').size

    CSV.foreach(csv_file, headers: true, encoding: 'bom|utf-8', liberal_parsing: true, skip_blanks: true, quote_char: "\x00") do |row|
      begin
        log_line = row['log_line'] || row.to_s
        next if log_line.nil? || log_line.strip.empty?

        parsed_ts = parse_timestamp_from_line(log_line) || (Time.parse(row['TimeCreated']) rescue nil)
        used_ts = parsed_ts || Time.now
        next if used_ts < start_time || used_ts > end_time

        if log_line =~ pat
          out_rows << [used_ts.strftime('%Y-%m-%d %H:%M:%S %z'), 'ALERT', tidy(log_line, 2000), File.basename(csv_file)]
          record_stat(:alerts_extracted)
        end

      rescue => row_error
        $logger.debug "Skipped malformed row in #{csv_file}: #{row_error.message}" if verbose
        record_stat(:processing_errors)
      ensure
        processed_lines += 1
        progress_bar(processed_lines, total_lines, prefix: "Filtering #{File.basename(csv_file)}")
      end
    end

  rescue CSV::MalformedCSVError => e
    $logger.error "Skipped entire CSV #{csv_file} due to malformed content: #{e.message}"
    record_stat(:processing_errors)
  end

  unless out_rows.length == 1
    FileUtils.mkdir_p(dest_folder)
    out_csv = File.join(dest_folder, "alerts_#{File.basename(csv_file)}")
    CSV.open(out_csv, 'w', encoding: 'utf-8') { |csv| out_rows.each { |r| csv << r } }
    $logger.info " Extracted #{out_rows.length - 1} alerts → #{File.basename(out_csv)}"
  end
end




def readable_from_csv(csv_path, out_path, opts = {})
  timestamp_fields = opts[:timestamp_fields] || ['TimeCreated','timestamp','time']
  id_fields = opts[:id_fields] || ['Id','EventID','Event']
  level_fields = opts[:level_fields] || ['LevelDisplayName','Level','Severity']
  source_fields = opts[:source_fields] || ['ProviderName','source','Source']
  message_fields = opts[:message_fields] || ['Message','MessageText','log_line','log']

  File.open(out_path, 'w', encoding: 'utf-8') do |out|
    out.puts "=" * 80
    out.puts "TripWire Readable Report"
    out.puts "Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
    out.puts "Source: #{File.basename(csv_path)}"
    out.puts "=" * 80
    out.puts

    begin
      CSV.foreach(csv_path, headers: true, encoding: 'bom|utf-8', skip_blanks: true) do |row|
        ts = nil
        timestamp_fields.each { |f| ts = row[f] if ts.nil? && row && row.headers.include?(f) && row[f] }
        ts ||= (row[0] rescue nil)
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

def build_readable_reports(csv_files, dest_folder, verbose: false)
  # Normalize to array
  csv_files = [csv_files] if csv_files.is_a?(String)

  total_files = csv_files.size
  processed = 0

  csv_files.each do |file|
    processed += 1

    progress_bar(processed, total_files, prefix: "Generating report for #{File.basename(file)}")

    next if File.directory?(file)

    begin
      next unless File.exist?(file)

      rows = CSV.read(
        file,
        headers: true,
        encoding: 'bom|utf-8',
        liberal_parsing: true,
        quote_char: "\x00"   
      )

      next if rows.empty?

      FileUtils.mkdir_p(dest_folder)
      report_file = File.join(dest_folder, "report_#{File.basename(file)}")

      File.open(report_file, 'w', encoding: 'utf-8') do |f|
        f.puts "Readable Report for #{File.basename(file)}"
        f.puts "-" * 60

        rows.each do |row|
          f.puts "#{row['TimeCreated']} | #{row['LevelDisplayName']} | #{row['ProviderName']} | #{row['Message']}"
        end
      end

    rescue CSV::MalformedCSVError => e
      $logger.error " Failed to generate report for #{file}: #{e.message}"
      record_stat(:processing_errors)

    rescue StandardError => e
      $logger.error " Failed to generate report for #{file}: #{e.message}"
      record_stat(:processing_errors)
      next
    end
  end
end



def system_snapshot(root, verbose: false)
  out = File.join(root, 'SystemSnapshot')
  FileUtils.mkdir_p(out)
  $logger.info "Capturing system snapshot"

  ps = <<~PS
    Get-CimInstance Win32_LogicalDisk | Export-Csv '#{out}/Disk.csv' -NoTypeInformation -Encoding utf8 -Force
    Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory | Export-Csv '#{out}/Memory.csv' -NoTypeInformation -Encoding utf8 -Force
    Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1 -MaxSamples 5 | Export-Csv '#{out}/CPU.csv' -NoTypeInformation -Encoding utf8 -Force
  PS

  success = run_powershell(ps, verbose: verbose)
  $logger.info "  ✓ Snapshot captured" if success
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
# TripWire Main Execution (example sequence)
# -----------------------------
puts <<~BANNER
  TripWire v#{TRIPWIRE_VERSION}
  Collecting logs from #{start_time} to #{end_time}
BANNER

# Example main sequence:
begin
  # 1) Windows Event logs
  unless options[:skip_windows]
    %w[System Application Security].each do |log|
      collect_windows_events(log, start_time, end_time, FOLDERS[:windows], verbose: options[:verbose])
    end
  end

  # 2) Collect file-based logs (datadog/postgresql)
  collect_logs_from_dir('Datadog', LOG_PATHS[:datadog], start_time, end_time, FOLDERS[:datadog], all_files: options[:all_files], verbose: options[:verbose]) if LOG_PATHS[:datadog]
  collect_logs_from_dir('PostgreSQL', LOG_PATHS[:postgresql], start_time, end_time, FOLDERS[:postgresql], all_files: options[:all_files], verbose: options[:verbose]) if LOG_PATHS[:postgresql]


  # 3) Include sample CSV if provided
  include_existing_csv(options[:sample_csv], FOLDERS[:datadog], start_time, end_time, verbose: options[:verbose]) if options[:sample_csv]

  # 4) Extract alerts from collected CSVs
  all_csvs = Dir.glob(File.join(ROOTDIR, '**', '*.csv'))
  all_csvs.each do |csvfile|
    extract_errors(csvfile, KEYWORDS, FOLDERS[:extracted], start_time, end_time, verbose: options[:verbose])
  end

  # 5) Generate human readable reports
  build_readable_reports(ROOTDIR, FOLDERS[:readable], verbose: options[:verbose])

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
