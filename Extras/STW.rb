#!/usr/bin/env ruby
# TripWire - Production Incident Detection System
# Version: 3.0
# Ruby: 2.5+
# Description: Collects and analyzes system logs for incident response

require 'fileutils'
require 'time'
require 'optparse'
require 'tempfile'
require 'logger'
require 'date'
require 'open3'
require 'timeout'

TRIPWIRE_VERSION = '3.0'
DEFAULT_HOURS = 24
PS_TIMEOUT = 60

KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
SECURITY_IDS = [4625, 4648, 4672, 4720, 4722, 4724, 4732, 4735, 4738, 4740, 4756, 1102].freeze

LOG_PATHS = {
  postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
  datadog: 'C:/ProgramData/Datadog/logs'
}.freeze

trap('INT') { puts "\n  Interrupted"; exit(130) }

# =============================================================================
# Utilities
# =============================================================================

$logger = Logger.new(STDOUT)
$logger.level = Logger::INFO
$logger.formatter = proc { |sev, time, _, msg| "[#{time.strftime('%H:%M:%S')}] #{sev[0]} | #{msg}\n" }

$stats = Hash.new(0)
$stats[:start] = Time.now

def stat(key, val = 1)
  $stats[key] += val
end

def tidy(msg, max = 1000)
  return '' unless msg
  msg.to_s.encode('UTF-8', invalid: :replace, undef: :replace)
    .gsub(/[\r\n\t]+/, ' ').strip[0...max]
rescue
  ''
end

def parse_ts(line)
  return nil unless line
  
  [/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/, 
   /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})/].each do |pat|
    return Time.parse($1) if line.match(pat)
  rescue
    next
  end
  nil
end

def severity(line, explicit = nil)
  return explicit.upcase if explicit&.strip&.size&.> 0
  case line.to_s
  when /\b(ERROR|FATAL|CRITICAL)\b/i then 'ERROR'
  when /\b(WARN|WARNING)\b/i then 'WARN'
  else 'INFO'
  end
end

def spinner(msg)
  return -> {} if $logger.level == Logger::DEBUG
  
  frames = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏]
  idx, running = 0, true
  
  t = Thread.new do
    while running
      print "\r#{frames[idx]} #{msg}..."
      idx = (idx + 1) % frames.size
      sleep 0.1
    end
  end
  
  -> { running = false; t.join; print "\r#{' ' * (msg.size + 20)}\r" }
end

# =============================================================================
# TSV Module
# =============================================================================

module TSV
  def self.write(file, rows)
    FileUtils.mkdir_p(File.dirname(file))
    File.open(file, 'w:UTF-8') { |f| rows.each { |r| f.puts clean(r).join("\t") } }
    true
  rescue => e
    $logger.error "TSV write failed: #{e.message}"
    false
  end

  def self.each(file)
    return unless File.exist?(file) && block_given?
    
    File.open(file, 'r:bom|utf-8') do |f|
      headers = f.readline.strip.split("\t", -1) rescue return
      f.each_line { |ln| yield Hash[headers.zip(ln.strip.split("\t", -1))] unless ln.strip.empty? }
    end
  rescue => e
    $logger.error "TSV read failed: #{e.message}"
  end

  def self.clean(row)
    row.map { |v| v.to_s.gsub(/[\t\r\n]+/, ' ').strip }
  end
end

# =============================================================================
# PowerShell
# =============================================================================

def find_powershell
  %w[pwsh powershell.exe].each do |cmd|
    return cmd if system("where #{cmd} >nul 2>&1")
  end
  
  ps = File.join(ENV['WINDIR'] || 'C:/Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe')
  return ps if File.exist?(ps)
  
  nil
end

def run_ps(script)
  ps_exe = find_powershell
  unless ps_exe
    $logger.warn "PowerShell not found, skipping"
    stat(:ps_missing)
    return false
  end

  tf = Tempfile.new(['tw', '.ps1'])
  tf.write(script)
  tf.close

  begin
    Timeout.timeout(PS_TIMEOUT) do
      stdout, stderr, status = Open3.capture3(ps_exe, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tf.path)
      
      $logger.debug "PS stdout: #{stdout[0...200]}" if stdout.size > 0
      $logger.debug "PS stderr: #{stderr[0...200]}" if stderr.size > 0
      
      unless status.success?
        $logger.warn "PowerShell failed (exit: #{status.exitstatus})"
        stat(:ps_failed)
        return false
      end
      
      return true
    end
  rescue Timeout::Error
    $logger.error "PowerShell timeout (#{PS_TIMEOUT}s)"
    stat(:ps_failed)
    false
  rescue => e
    $logger.error "PowerShell error: #{e.message}"
    stat(:ps_failed)
    false
  ensure
    tf.unlink rescue nil
  end
end

# =============================================================================
# Time Range Parser
# =============================================================================

def parse_time_range(opts)
  now = Time.now
  
  case opts[:mode]
  when :today
    midnight = Time.new(now.year, now.month, now.day, 0, 0, 0)
    [midnight, midnight + 86400 - 1]
    
  when :yesterday
    midnight = Time.new(now.year, now.month, now.day, 0, 0, 0)
    [midnight - 86400, midnight - 1]
    
  when :last
    if opts[:duration] =~ /^(\d+)([hdwm])$/i
      amt, unit = $1.to_i, $2.downcase
      sec = case unit
            when 'h' then amt * 3600
            when 'd' then amt * 86400
            when 'w' then amt * 604800
            when 'm' then amt * 2592000
            end
      [now - sec, now]
    else
      $logger.fatal "Invalid --last format (use: 6h, 2d, 1w, 1m)"
      exit(1)
    end
    
  when :back
    spec = opts[:duration].to_s
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
    
    target = dt.to_time
    [target, target + 86400 - 1]
    
  else
    [now - DEFAULT_HOURS * 3600, now]
  end
end

# =============================================================================
# Collection Functions
# =============================================================================

def collect_windows(log, start_t, end_t, out_dir, opts = {})
  tsv = File.join(out_dir, log, "#{log}.tsv")
  FileUtils.mkdir_p(File.dirname(tsv))
  
  $logger.info "Collecting Windows #{log}..."
  
  filters = [
    "LogName='#{log}'",
    "StartTime=$start",
    "EndTime=$end"
  ]
  
  if log == 'Security' && !opts[:all_sec] && SECURITY_IDS
    filters << "ID=#{SECURITY_IDS.join(',')}"
  end
  
  if log != 'Security' && !opts[:all_levels]
    filters << "Level=1,2,3"
  end
  
  ps = <<~PS
    $start = [datetime]'#{start_t.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
    $end = [datetime]'#{end_t.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
    $filter = @{#{filters.join('; ')}}
    
    try {
      $evt = Get-WinEvent -FilterHashtable $filter -MaxEvents 10000 -EA Stop |
        Select TimeCreated,Id,LevelDisplayName,ProviderName,Message
      
      if ($evt) {
        $evt | ConvertTo-Csv -Delimiter "`t" -NoType |
          Out-File '#{tsv}' -Encoding utf8 -Force
      } else {
        "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" |
          Out-File '#{tsv}' -Encoding utf8 -Force
      }
    } catch {
      "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" |
        Out-File '#{tsv}' -Encoding utf8 -Force
    }
  PS
  
  stop = spinner("#{log} events")
  ok = run_ps(ps)
  stop.call
  
  TSV.write(tsv, [%w[TimeCreated Id LevelDisplayName ProviderName Message]]) unless ok
  
  count = File.exist?(tsv) ? [File.readlines(tsv).count - 1, 0].max : 0
  stat(:lines, count)
  stat(:files)
  
  $logger.info "  ✓ #{count} events"
rescue => e
  $logger.error "Windows #{log} failed: #{e.message}"
  stat(:errors)
end

def collect_files(name, path, start_t, end_t, out_dir, opts = {})
  tsv = File.join(out_dir, "#{name}.tsv")
  $logger.info "Collecting #{name}..."
  
  unless Dir.exist?(path)
    $logger.warn "  Not found: #{path}"
    TSV.write(tsv, [%w[timestamp severity message source]])
    return
  end
  
  rows = [%w[timestamp severity message source]]
  files = 0
  
  Dir.glob(File.join(path, '**', '*')).sort.each do |f|
    next unless File.file?(f)
    
    mtime = File.mtime(f) rescue next
    next if !opts[:all_files] && (mtime < start_t || mtime > end_t)
    
    files += 1
    
    File.foreach(f, encoding: 'bom|utf-8') do |line|
      ts = parse_ts(line) || mtime
      next unless ts.between?(start_t, end_t)
      
      sev = severity(line)
      rows << [ts.strftime('%Y-%m-%d %H:%M:%S'), sev, tidy(line), File.basename(f)]
      
      stat(:lines)
      stat(:errors) if sev == 'ERROR'
      stat(:warns) if sev == 'WARN'
    end
  rescue => e
    $logger.debug "Skipped #{f}: #{e.message}"
  end
  
  TSV.write(tsv, rows)
  stat(:files, files)
  
  $logger.info "  ✓ #{files} files, #{rows.size - 1} lines"
rescue => e
  $logger.error "#{name} failed: #{e.message}"
  stat(:errors)
end

def extract_alerts(root, start_t, end_t, out_dir)
  $logger.info "Extracting alerts..."
  
  pattern = Regexp.union(KEYWORDS.map { |k| /\b#{k}\b/i })
  
  Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
    next if tsv.include?('/Alerts/')
    
    alerts = [%w[timestamp severity message source]]
    
    TSV.each(tsv) do |row|
      msg = row['message'] || row['Message'] || row.values.join(' ')
      next unless msg.match?(pattern)
      
      ts_str = row['TimeCreated'] || row['timestamp'] || row.values.first
      ts = (Time.parse(ts_str) rescue Time.now)
      next unless ts.between?(start_t, end_t)
      
      alerts << [ts.strftime('%Y-%m-%d %H:%M:%S'), 'ALERT', tidy(msg, 2000), File.basename(tsv)]
      stat(:alerts)
    end
    
    if alerts.size > 1
      out = File.join(out_dir, "alerts_#{File.basename(tsv)}")
      TSV.write(out, alerts)
      $logger.info "  #{alerts.size - 1} alerts"
    end
  end
rescue => e
  $logger.error "Alert extraction failed: #{e.message}"
end

def create_reports(root, out_dir)
  $logger.info "Generating reports..."
  
  Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
    rpt = File.join(out_dir, "#{File.basename(tsv, '.tsv')}.txt")
    FileUtils.mkdir_p(File.dirname(rpt))
    
    File.open(rpt, 'w:UTF-8') do |f|
      f.puts "=" * 80
      f.puts "TripWire Report: #{File.basename(tsv)}"
      f.puts "=" * 80
      f.puts
      
      count = 0
      TSV.each(tsv) do |row|
        ts = row['TimeCreated'] || row['timestamp'] || Time.now.to_s
        ts = (Time.parse(ts).strftime('%Y-%m-%d %H:%M:%S') rescue ts[0...19])
        
        lvl = row['LevelDisplayName'] || row['severity'] || 'INFO'
        msg = row['Message'] || row['message'] || ''
        src = row['ProviderName'] || row['source'] || File.basename(tsv)
        eid = row['Id'] || row['EventID'] || ''
        
        f.puts "[#{ts}] #{lvl.ljust(8)} | #{src[0...40].ljust(40)} | #{tidy(msg)}#{eid.empty? ? '' : " [#{eid}]"}"
        count += 1
      end
      
      f.puts "\nTotal: #{count} events"
    end
  rescue => e
    $logger.debug "Report skipped: #{e.message}"
  end
end

def snapshot(out_dir)
  $logger.info "Capturing snapshot..."
  
  ps = <<~PS
    Get-CimInstance Win32_LogicalDisk |
      ConvertTo-Csv -Delimiter "`t" -NoType |
      Out-File '#{File.join(out_dir, 'disk.tsv')}' -Encoding utf8 -Force
    
    Get-CimInstance Win32_OperatingSystem |
      Select TotalVisibleMemorySize,FreePhysicalMemory |
      ConvertTo-Csv -Delimiter "`t" -NoType |
      Out-File '#{File.join(out_dir, 'memory.tsv')}' -Encoding utf8 -Force
  PS
  
  stop = spinner("Snapshot")
  ok = run_ps(ps)
  stop.call
  
  $logger.info "  ✓ Snapshot #{ok ? 'captured' : 'skipped'}"
rescue => e
  $logger.error "Snapshot failed: #{e.message}"
end

# =============================================================================
# Main
# =============================================================================

opts = {
  mode: :default,
  verbose: false,
  all_files: false,
  skip_windows: false,
  skip_snapshot: false,
  parallel: false,
  all_sec: false,
  all_levels: false,
  log_paths: LOG_PATHS.dup
}

OptionParser.new do |op|
  op.banner = "TripWire v#{TRIPWIRE_VERSION}\n\nUsage: ruby tripwire.rb [options]"
  
  op.on('--last DUR', 'Last duration (6h, 2d, 1w, 1m)') { |d| opts[:mode] = :last; opts[:duration] = d }
  op.on('--back DUR', 'Past offset (2m1w3d)') { |d| opts[:mode] = :back; opts[:duration] = d }
  op.on('--today', 'Today') { opts[:mode] = :today }
  op.on('--yesterday', 'Yesterday') { opts[:mode] = :yesterday }
  op.on('--verbose', 'Verbose') { opts[:verbose] = true }
  op.on('--skip-windows', 'Skip Windows logs') { opts[:skip_windows] = true }
  op.on('--skip-snapshot', 'Skip snapshot') { opts[:skip_snapshot] = true }
  op.on('--parallel', 'Parallel Windows collection') { opts[:parallel] = true }
  op.on('--all-security', 'All security events') { opts[:all_sec] = true }
  op.on('--all-levels', 'All event levels') { opts[:all_levels] = true }
  op.on('--datadog PATH', 'Datadog path') { |p| opts[:log_paths][:datadog] = p }
  op.on('--postgres PATH', 'PostgreSQL path') { |p| opts[:log_paths][:postgresql] = p }
  op.on('-h', '--help') { puts op; exit }
  op.on('--version') { puts "TripWire v#{TRIPWIRE_VERSION}"; exit }
end.parse!

$logger.level = Logger::DEBUG if opts[:verbose]

begin
  start_t, end_t = parse_time_range(opts)
  
  incident_t = Time.now
  root = File.join(Dir.pwd, "TripWire_#{incident_t.strftime('%Y%m%d-%H%M%S')}")
  
  dirs = {
    win: File.join(root, 'Windows'),
    dog: File.join(root, 'Datadog'),
    pg: File.join(root, 'PostgreSQL'),
    alerts: File.join(root, 'Alerts'),
    reports: File.join(root, 'Reports'),
    snap: File.join(root, 'Snapshot')
  }
  
  dirs.values.each { |d| FileUtils.mkdir_p(d) }
  
  summary = File.join(root, 'summary.log')
  $summary = Logger.new(summary)
  $summary.formatter = proc { |_, _, _, m| "#{m}\n" }
  
  puts <<~BANNER

    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║   ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗          ║
    ║   ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝          ║
    ║      ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗            ║
    ║      ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝            ║
    ║      ██║   ██║  ██║██║██║     ╚███╔███╔╝██║██║  ██║███████╗          ║
    ║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝          ║
    ║                                                                      ║
    ║            Incident Detection System v#{TRIPWIRE_VERSION.center(22)}         ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝

    Time: #{start_t.strftime('%Y-%m-%d %H:%M')} → #{end_t.strftime('%Y-%m-%d %H:%M')}
    Output: #{root}

  BANNER
  
  # Windows events
  if !opts[:skip_windows] && Gem.win_platform?
    logs = %w[System Application Security]
    
    if opts[:parallel]
      threads = logs.map { |log| Thread.new { collect_windows(log, start_t, end_t, dirs[:win], opts) } }
      threads.each(&:join)
    else
      logs.each { |log| collect_windows(log, start_t, end_t, dirs[:win], opts) }
    end
  end
  
  # File logs
  collect_files('Datadog', opts[:log_paths][:datadog], start_t, end_t, dirs[:dog], opts) if opts[:log_paths][:datadog]
  collect_files('PostgreSQL', opts[:log_paths][:postgresql], start_t, end_t, dirs[:pg], opts) if opts[:log_paths][:postgresql]
  
  # Alerts & reports
  extract_alerts(root, start_t, end_t, dirs[:alerts])
  create_reports(root, dirs[:reports])
  
  # Snapshot
  snapshot(dirs[:snap]) if !opts[:skip_snapshot] && Gem.win_platform?
  
  # Summary
  elapsed = Time.now - $stats[:start]
  
  sum = <<~SUM
    ═════════════════════════════════════════════════════════════════
    TripWire v#{TRIPWIRE_VERSION} - Summary
    ═════════════════════════════════════════════════════════════════
    
    Started:  #{incident_t.strftime('%Y-%m-%d %H:%M:%S')}
    Duration: #{sprintf('%.2f', elapsed)}s
    Range:    #{start_t.strftime('%Y-%m-%d %H:%M')} → #{end_t.strftime('%Y-%m-%d %H:%M')}
    
    Files:    #{$stats[:files]}
    Lines:    #{$stats[:lines]}
    Errors:   #{$stats[:errors]}
    Warnings: #{$stats[:warns]}
    Alerts:   #{$stats[:alerts]}
    
    Output:   #{root}
    ═════════════════════════════════════════════════════════════════
  SUM
  
  File.write(File.join(root, 'SUMMARY.txt'), sum)
  puts "\n#{sum}\n✅ Complete!\n"
  
rescue => e
  $logger.fatal "Fatal: #{e.message}"
  $logger.debug e.backtrace.join("\n") if opts[:verbose]
  exit(2)
end