#!/usr/bin/env ruby
# TripWire v3.1.1 - Incident Detection System (refactor)
# Ruby 2.5+ | Collects Windows Events, file logs, generates reports
#
# Notes:
# - Keeps same behaviour and CLI as previous versions.
# - Hardened PowerShell interaction, TSV handling, timestamp parsing and reporting.
# - Designed to run on Windows for full feature set (Get-WinEvent + snapshot).
# - Works on other platforms for file-based logs and report generation.

require 'fileutils'
require 'time'
require 'optparse'
require 'tempfile'
require 'logger'
require 'date'
require 'open3'
require 'timeout'

VERSION = '3.1.1'
PS_TIMEOUT = 60
KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
SECURITY_IDS = [4625, 4648, 4672, 4720, 4722, 4724, 4732, 4735, 4738, 4740, 4756, 1102].freeze

LOG_PATHS = {
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
  datadog: 'C:/ProgramData/Datadog/logs'
}.freeze

trap('INT') { puts "\nInterrupted"; exit(130) }

# ----------------------------
# Logging / Stats / Utilities
# ----------------------------
$log = Logger.new(STDOUT)
$log.level = Logger::INFO
$log.formatter = proc { |sev, time, _, msg| "[#{time.strftime('%H:%M:%S')}] #{sev[0]} | #{msg}\n" }

$stats = Hash.new(0)
$stats[:start] = Time.now

def stat(key, val = 1)
  $stats[key] += val
end

def tidy(s, max = 1000)
  return '' if s.nil?
  s = s.to_s.encode('UTF-8', invalid: :replace, undef: :replace)
  s = s.gsub(/[\r\n\t]+/, ' ')
  s = s.gsub(/\s+/, ' ').strip
  s[0...max]
rescue
  ''
end

def parse_ts(line)
  return nil if line.nil? || line.empty?

  patterns = [
    /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)/,
    /([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})/
  ]

  patterns.each do |pat|
    m = pat.match(line)
    next unless m
    begin
      return Time.parse(m[1].gsub(/\s+UTC$/, ''))
    rescue
      next
    end
  end
  nil
end

def severity(line, explicit = nil)
  if explicit && explicit.to_s.strip.size > 0
    return explicit.to_s.upcase
  end

  case line.to_s
  when /\b(ERROR|FATAL|CRITICAL)\b/i then 'ERROR'
  when /\b(WARN|WARNING)\b/i then 'WARN'
  else 'INFO'
  end
end

def spinner(msg)
  return -> {} if $log.level == Logger::DEBUG

  frames = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏]
  idx = 0
  running = true
  t = Thread.new do
    while running
      print "\r#{frames[idx]} #{msg}..."
      idx = (idx + 1) % frames.length
      sleep 0.10
    end
  end

  -> {
    running = false
    t.join
    print "\r#{' ' * (msg.length + 20)}\r"
  }
end

# ----------------------------
# TSV helpers
# ----------------------------
module TSV
  module_function

  def write(path, rows)
    begin
      FileUtils.mkdir_p(File.dirname(path))
      File.open(path, 'w:UTF-8') do |f|
        rows.each do |r|
          f.puts r.map { |v| v.to_s.gsub(/[\t\r\n]+/, ' ').strip }.join("\t")
        end
      end
      true
    rescue => e
      $log.error "TSV write failed (#{path}): #{e.message}"
      false
    end
  end

  def each(path)
    return unless File.exist?(path) && block_given?
    File.open(path, 'r:bom|utf-8') do |f|
      header_line = f.gets
      return if header_line.nil?
      headers = header_line.strip.split("\t", -1)
      f.each_line do |ln|
        next if ln.nil?
        ln = ln.strip
        next if ln.empty?
        values = ln.split("\t", -1)
        yield Hash[headers.zip(values)]
      end
    end
  rescue => e
    $log.error "TSV read failed (#{path}): #{e.message}"
  end
end

# ----------------------------
# PowerShell
# ----------------------------
def find_powershell
  # prefer pwsh, then powershell.exe, else fallback to System32 path
  %w[pwsh powershell.exe].each do |cmd|
    begin
      return cmd if system("where #{cmd} >nul 2>&1")
    rescue
      # ignore platform issues with `where`
    end
  end
  ps = File.join(ENV['WINDIR'] || 'C:/Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe')
  return ps if File.exist?(ps)
  nil
end

def run_ps(script)
  ps = find_powershell
  unless ps
    $log.warn "PowerShell not found; skipping PowerShell operation"
    stat(:ps_missing)
    return false
  end

  tf = Tempfile.new(['tripwire', '.ps1'])
  begin
    tf.write(script)
    tf.close

    begin
      Timeout.timeout(PS_TIMEOUT) do
        stdout, stderr, status = Open3.capture3(ps, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tf.path)
        $log.debug("PS stdout: #{stdout[0...400]}") if stdout && stdout.length > 0
        $log.debug("PS stderr: #{stderr[0...400]}") if stderr && stderr.length > 0

        unless status.success?
          $log.warn "PowerShell returned non-zero exit (#{status.exitstatus})"
          stat(:ps_fail)
          return false
        end

        return true
      end
    rescue Timeout::Error
      $log.error "PowerShell timed out after #{PS_TIMEOUT}s"
      stat(:ps_fail)
      return false
    end
  rescue => e
    $log.error "PowerShell error: #{e.message}"
    stat(:ps_fail)
    false
  ensure
    tf.unlink rescue nil
  end
end

# ----------------------------
# Time range parsing
# ----------------------------
def time_range(opts)
  now = Time.now
  case opts[:mode]
  when :today
    mid = Time.new(now.year, now.month, now.day, 0, 0, 0)
    [mid, mid + 86_399]
  when :yesterday
    mid = Time.new(now.year, now.month, now.day, 0, 0, 0)
    [mid - 86_400, mid - 1]
  when :last
    if opts[:dur] =~ /^(\d+)([hdwm])$/i
      amount = $1.to_i
      unit = $2.downcase
      seconds = case unit
                when 'h' then amount * 3600
                when 'd' then amount * 86_400
                when 'w' then amount * 604_800
                when 'm' then amount * 2_592_000
                end
      [now - seconds, now]
    else
      $log.fatal "Invalid --last format; use: 6h, 2d, 1w, 1m"
      exit(1)
    end
  when :back
    # parse xM xW xD xH style
    spec = opts[:dur].to_s
    months = weeks = days = hours = 0
    spec.scan(/(\d+)([mwdh])/i).each do |n, u|
      case u.downcase
      when 'm' then months += n.to_i
      when 'w' then weeks += n.to_i
      when 'd' then days += n.to_i
      when 'h' then hours += n.to_i
      end
    end
    dt = now.to_datetime << months
    dt -= (weeks * 7 + days)
    dt -= Rational(hours, 24)
    t = dt.to_time
    [t, t + 86_399]
  else
    [now - DEFAULT_HOURS * 3600, now]
  end
end

# ----------------------------
# Collect Windows Events
# ----------------------------
def collect_win(log_name, start_t, end_t, out_dir, opts = {})
  tsv = File.join(out_dir, log_name, "#{log_name}.tsv")
  FileUtils.mkdir_p(File.dirname(tsv))
  $log.info "Collecting Windows #{log_name} events..."

  filters = ["LogName='#{log_name}'", "StartTime=$start", "EndTime=$end"]
  if log_name == 'Security' && !opts[:all_sec]
    filters << "Id=#{SECURITY_IDS.join(',')}"
  end
  filters << "Level=1,2,3" if log_name != 'Security' && !opts[:all_lvl]

  ps = <<~PS
    $start = [datetime]'#{start_t.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
    $end = [datetime]'#{end_t.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
    try {
      $e = Get-WinEvent -FilterHashtable @{#{filters.join('; ')}} -MaxEvents 10000 -EA Stop |
        Select TimeCreated,Id,LevelDisplayName,ProviderName,Message
      if ($e) {
        $e | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation | Out-File '#{tsv}' -Encoding utf8 -Force
      } else {
        "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force
      }
    } catch {
      "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force
    }
  PS

  stop = spinner("Reading #{log_name}")
  ok = run_ps(ps)
  stop.call

  # ensure header exists if file is empty
  if File.exist?(tsv) && File.zero?(tsv)
    TSV.write(tsv, [%w[TimeCreated Id LevelDisplayName ProviderName Message]])
  end

  cnt = File.exist?(tsv) ? [File.readlines(tsv, encoding: 'bom|utf-8').count - 1, 0].max : 0
  stat(:lines, cnt)
  stat(:files)
  $log.info "  ✓ #{cnt} events"
rescue => e
  $log.error "collect_win(#{log_name}): #{e.message}"
  stat(:err)
end

# ----------------------------
# Collect file logs (Datadog/Postgres etc.)
# ----------------------------
def collect_files(name, path, start_t, end_t, out_dir, opts = {})
  tsv = File.join(out_dir, "#{name}.tsv")
  $log.info "Collecting files: #{name} from #{path}"

  unless Dir.exist?(path)
    $log.warn "  Path not found: #{path}"
    TSV.write(tsv, [%w[timestamp severity message source]])
    return
  end

  rows = [%w[timestamp severity message source]]
  files = 0

  Dir.glob(File.join(path, '**', '*')).sort.each do |f|
    next unless File.file?(f)
    begin
      mtime = File.mtime(f) rescue next
      next if !opts[:all_files] && (mtime < start_t || mtime > end_t)

      files += 1
      File.foreach(f, encoding: 'bom|utf-8') do |ln|
        ts = parse_ts(ln) || mtime
        next unless ts.between?(start_t, end_t)
        sev = severity(ln)
        rows << [ts.strftime('%Y-%m-%d %H:%M:%S'), sev, tidy(ln), File.basename(f)]
        stat(:lines)
        stat(:err) if sev == 'ERROR'
        stat(:warn) if sev == 'WARN'
      end
    rescue => e
      $log.debug "Skipped file #{f}: #{e.message}"
      next
    end
  end

  TSV.write(tsv, rows)
  stat(:files, files)
  $log.info "  ✓ #{files} files, #{rows.size - 1} lines"
rescue => e
  $log.error "collect_files(#{name}): #{e.message}"
  stat(:err)
end

# ----------------------------
# Extract alerts
# ----------------------------
def extract_alerts(root_dir, start_t, end_t, out_dir)
  $log.info "Extracting alerts..."
  pat = Regexp.union(KEYWORDS.map { |k| /\b#{Regexp.escape(k)}\b/i })

  Dir.glob(File.join(root_dir, '**', '*.tsv')).reject { |p| p.include?(File.join(File::SEPARATOR, 'Alerts' + File::SEPARATOR)) }.each do |tsv|
    alerts = [%w[timestamp severity message source]]
    TSV.each(tsv) do |row|
      msg = row['message'] || row['Message'] || row.values.join(' ')
      next unless msg && msg.match?(pat)
      raw_ts = row['TimeCreated'] || row['timestamp'] || row.values.first
      ts = (Time.parse(raw_ts) rescue Time.now)
      next unless ts.between?(start_t, end_t)
      alerts << [ts.strftime('%Y-%m-%d %H:%M:%S'), 'ALERT', tidy(msg, 2000), File.basename(tsv)]
      stat(:alerts)
    end

    if alerts.size > 1
      out_file = File.join(out_dir, "alerts_#{File.basename(tsv)}")
      TSV.write(out_file, alerts)
      $log.info "  🚨 #{alerts.size - 1} alerts from #{File.basename(tsv)}"
    end
  end
rescue => e
  $log.error "extract_alerts: #{e.message}"
end

# ----------------------------
# Create human-readable reports
# ----------------------------
def create_reports(root_dir, out_dir)
  $log.info "Generating reports..."
  Dir.glob(File.join(root_dir, '**', '*.tsv')).each do |tsv|
    begin
      # build a relative, safe report name
      rel = tsv.sub(root_dir + File::SEPARATOR, '').gsub(/[\\\/]/, '_')
      rpt_name = rel.sub(/\.tsv$/i, '.txt')
      rpt = File.join(out_dir, rpt_name)
      FileUtils.mkdir_p(File.dirname(rpt))

      count = 0
      empty_rows = 0

      File.open(rpt, 'w:UTF-8') do |f|
        f.puts "=" * 80
        f.puts "TripWire Report: #{rpt_name}"
        f.puts "Source TSV: #{tsv}"
        f.puts "=" * 80
        f.puts

        TSV.each(tsv) do |row|
          values = row.values.map { |v| v.to_s.strip }
          if values.all?(&:empty?)
            empty_rows += 1
            next
          end

          raw_ts = row['TimeCreated'] || row['timestamp'] || row['time']
          ts = (Time.parse(raw_ts) rescue Time.now)
          ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') rescue raw_ts.to_s[0...19]

          lvl = (row['LevelDisplayName'] || row['Level'] || row['severity'] || 'INFO').to_s.strip
          lvl = 'INFO' if lvl.empty?

          msg = row['Message'] || row['message'] || row['log_line'] || row.values.join(' | ')
          msg = tidy(msg)

          next if msg.nil? || msg.strip.empty?

          src = (row['ProviderName'] || row['source'] || File.basename(tsv)).to_s.strip
          src = File.basename(tsv) if src.empty?

          eid = (row['Id'] || row['EventID'] || row['Event'] || '').to_s.strip
          evt_part = eid.empty? ? '' : " [#{eid}]"

          f.puts "[#{ts_str}] #{lvl.ljust(8)} | #{src[0...40].ljust(40)} | #{msg}#{evt_part}"
          count += 1
        end

        f.puts
        f.puts "=" * 80
        f.puts "Total: #{count} events"
        f.puts "Empty rows skipped: #{empty_rows}" if empty_rows > 0
        f.puts "=" * 80
      end

      $log.debug "Created report: #{rpt_name} (#{count} events, #{empty_rows} empty)" if $log.level == Logger::DEBUG
    rescue => e
      $log.error "create_reports(#{tsv}): #{e.message}"
      $log.debug e.backtrace.join("\n") if $log.level == Logger::DEBUG
    end
  end
end

# ----------------------------
# Snapshot
# ----------------------------
def snapshot(dir)
  $log.info "Capturing system snapshot..."
  FileUtils.mkdir_p(dir)

  ps = <<~PS
    Get-CimInstance Win32_LogicalDisk |
      ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
      Out-File '#{File.join(dir, 'disk.tsv')}' -Encoding utf8 -Force

    Get-CimInstance Win32_OperatingSystem |
      Select TotalVisibleMemorySize,FreePhysicalMemory |
      ConvertTo-Csv -Delimiter "`t" -NoTypeInformation |
      Out-File '#{File.join(dir, 'memory.tsv')}' -Encoding utf8 -Force
  PS

  stop = spinner("Snapshot")
  ok = run_ps(ps)
  stop.call
  $log.info "  ✓ Snapshot #{ok ? 'captured' : 'skipped'}"
rescue => e
  $log.error "snapshot: #{e.message}"
end

# ----------------------------
# Main
# ----------------------------
DEFAULT_HOURS = 24 unless defined?(DEFAULT_HOURS)

opts = {
  mode: :default,
  dur: '24h',
  verbose: false,
  all_files: false,
  skip_win: false,
  skip_snap: false,
  parallel: false,
  all_sec: false,
  all_lvl: false,
  paths: LOG_PATHS.dup
}

OptionParser.new do |o|
  o.banner = "TripWire v#{VERSION}\n\nUsage: ruby tripwire.rb [options]"
  o.on('--last D', 'Duration (6h, 2d, 1w, 1m)') { |d| opts[:mode] = :last; opts[:dur] = d }
  o.on('--back D', 'Offset (2m1w3d)') { |d| opts[:mode] = :back; opts[:dur] = d }
  o.on('--today', 'Today') { opts[:mode] = :today }
  o.on('--yesterday', 'Yesterday') { opts[:mode] = :yesterday }
  o.on('--verbose', 'Verbose') { opts[:verbose] = true; $log.level = Logger::DEBUG }
  o.on('--skip-windows', 'Skip Windows log collection') { opts[:skip_win] = true }
  o.on('--skip-snapshot', 'Skip system snapshot') { opts[:skip_snap] = true }
  o.on('--parallel', 'Parallel Windows collection') { opts[:parallel] = true }
  o.on('--all-security', 'Collect all security events') { opts[:all_sec] = true }
  o.on('--all-levels', 'Collect all event levels') { opts[:all_lvl] = true }
  o.on('--datadog PATH', 'Datadog path') { |p| opts[:paths][:datadog] = p }
  o.on('--postgres PATH', 'PostgreSQL path') { |p| opts[:paths][:postgresql] = p }
  o.on('-h', '--help', 'Help') { puts o; exit }
  o.on('--version', 'Version') { puts "TripWire v#{VERSION}"; exit }
end.parse!

begin
  st, et = time_range(opts)
  incident_t = Time.now
  root = File.join(Dir.pwd, "TripWire_#{incident_t.strftime('%Y%m%d-%H%M%S')}")
  dirs = {
    win: File.join(root, 'Windows'),
    dog: File.join(root, 'Datadog'),
    pg: File.join(root, 'PostgreSQL'),
    alerts: File.join(root, 'Alerts'),
    rpt: File.join(root, 'Reports'),
    snap: File.join(root, 'Snapshot')
  }
  dirs.values.each { |d| FileUtils.mkdir_p(d) }

  summary_log = File.join(root, 'summary.log')
  $summary = Logger.new(summary_log)
  $summary.formatter = proc { |_, _, _, m| "#{m}\n" }

  puts <<~BANNER

    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║   ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗          ║
    ║   ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝          ║
    ║      ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗            ║
    ║      ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝            ║
    ║      ██║   ██║  ██║██║██║     ╚███╔╝██╔╝██║██║  ██║███████╗          ║
    ║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝          ║
    ║                                                                      ║
    ║            Incident Detection System v#{VERSION.center(22)}         ║
    ╚══════════════════════════════════════════════════════════════════════╝

    Time Range: #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}
    Output: #{root}

  BANNER

  # Windows events (only if platform supports)
  if !opts[:skip_win] && Gem.win_platform?
    logs = %w[System Application Security]
    if opts[:parallel]
      threads = logs.map { |ln| Thread.new { collect_win(ln, st, et, dirs[:win], all_sec: opts[:all_sec], all_lvl: opts[:all_lvl]) } }
      threads.each(&:join)
    else
      logs.each { |ln| collect_win(ln, st, et, dirs[:win], all_sec: opts[:all_sec], all_lvl: opts[:all_lvl]) }
    end
  else
    $log.info "Skipping Windows event collection (either skipped or not Windows)"
  end

  # File logs
  collect_files('Datadog', opts[:paths][:datadog], st, et, dirs[:dog], all_files: opts[:all_files]) if opts[:paths][:datadog]
  collect_files('PostgreSQL', opts[:paths][:postgresql], st, et, dirs[:pg], all_files: opts[:all_files]) if opts[:paths][:postgresql]

  # Alerts & Reports
  extract_alerts(root, st, et, dirs[:alerts])
  create_reports(root, dirs[:rpt])

  # Snapshot (Windows only)
  snapshot(dirs[:snap]) if !opts[:skip_snap] && Gem.win_platform?

  # Summary
  elapsed = Time.now - $stats[:start]
  sum = <<~SUM
    ═════════════════════════════════════════════════════════════════
    TripWire v#{VERSION} - Summary
    ═════════════════════════════════════════════════════════════════
    Duration: #{sprintf('%.2f', elapsed)}s
    Range:    #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}
    Files:    #{$stats[:files]} | Lines: #{$stats[:lines]} | Errors: #{$stats[:err]} | Warnings: #{$stats[:warn]} | Alerts: #{$stats[:alerts]}
    Output:   #{root}
    ═════════════════════════════════════════════════════════════════
  SUM

  File.write(File.join(root, 'SUMMARY.txt'), sum)
  puts "\n#{sum}\n✅ Complete!\n"

rescue => e
  $log.fatal "Fatal error: #{e.message}"
  $log.debug(e.backtrace.join("\n")) if opts[:verbose]
  exit(2)
end
