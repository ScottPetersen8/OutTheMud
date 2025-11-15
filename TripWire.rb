#!/usr/bin/env ruby
require 'fileutils'
require 'time'
require 'csv'

# === DEFAULTS ===
TIME_RANGE_HOURS = 24
KEYWORDS = ["shutdown", "crash", "panic", "fail", "error", "critical", "fatal"]

def progress(msg)
  print "[*] #{msg}..."
  sleep 0.4
  puts "done."
end

# === CLI FLAGS ===
hours = TIME_RANGE_HOURS
if ARGV.include?("--yesterday")
  hours = 24
elsif ARGV.include?("--today")
  hours = 12
elsif i = ARGV.index("--hours")
  hours = ARGV[i + 1].to_i
end

# === OUTPUT ROOT ===
incident_time = Time.now
ROOTDIR = File.join(Dir.pwd, "incident_collection_#{incident_time.strftime('%Y%m%d_%H%M')}")
FileUtils.mkdir_p(ROOTDIR)

# === WINDOWS EVENT LOG COLLECTION ===
def collect_windows_events(log, hours, root)
  out_dir = File.join(root, "WindowsEvent_#{log}")
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{log}_events.csv")

  progress "Collecting Windows #{log} events (last #{hours}h)"

  ps = <<-PS
    $since = (Get-Date).AddHours(-#{hours})
    $filter = @{LogName='#{log}'; StartTime=$since}
    try {
      $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Select TimeCreated,Id,LevelDisplayName,Message
      if ($events.Count -eq 0) {
        "timestamp,severity,log_line,source" | Out-File -Encoding utf8 '#{csv_file}'
      } else {
        $events | Export-Csv -Path '#{csv_file}' -NoTypeInformation -Encoding utf8
      }
    } catch {
      "timestamp,severity,log_line,source" | Out-File -Encoding utf8 '#{csv_file}'
    }
  PS

  system("powershell -NoProfile -Command \"#{ps.gsub("\"", "\\\"")}\"")
end

# === GENERIC LOG COLLECTION ===
def collect_logs_from_dir(name, path, hours, root)
  out_dir = File.join(root, name)
  FileUtils.mkdir_p(out_dir)
  csv_file = File.join(out_dir, "#{name}.csv")

  progress "Collecting logs from #{name}"

  return File.write(csv_file, "timestamp,severity,log_line,source\n") unless Dir.exist?(path)

  rows = [["timestamp", "severity", "log_line", "source"]]

  Dir.glob("#{path}/*").each do |file|
    next unless File.file?(file)
    next if (Time.now - File.mtime(file)) / 3600 > hours

    File.readlines(file, errors: :replace).each do |line|
      rows << [Time.now, "INFO", line.strip, File.basename(file)]
    end
  end

  CSV.open(csv_file, "w") { |csv| rows.each { |r| csv << r } }
end

# === ERROR FILTER PASS (RUBY 2.3 SAFE) ===
def extract_errors(csv_file, keywords)
  return unless File.exist?(csv_file)
  progress "Filtering errors in #{File.basename(csv_file)}"

  pattern = Regexp.new(keywords.join("|"), Regexp::IGNORECASE)
  rows = [["timestamp", "severity", "log_line", "source"]]

  begin
    File.readlines(csv_file, errors: :replace).each_with_index do |line, idx|
      next if idx == 0  # skip header
      if line =~ pattern
        rows << [Time.now, "ALERT", line.strip, File.basename(csv_file)]
      end
    end
  rescue => e
    puts "[!] Failed to read #{csv_file}: #{e}"
  end

  # -----------------------------
# Readable log formatter helpers
# Add this AFTER log collection & error extraction, BEFORE packaging
# -----------------------------
require 'time'

# sanitize text, remove newlines, trim long messages
def tidy(msg, max_len = 400)
  return "" if msg.nil?
  s = msg.to_s.encode('UTF-8', :invalid => :replace, :undef => :replace, :replace => '?')
  s = s.gsub(/\r?\n/, ' ').strip
  s.length > max_len ? (s[0...max_len] + '...') : s
end

# try CSV parsing, fallback to raw-lines parsing
def readable_from_csv(csv_path, out_path, opts = {})
  headers_expected = opts[:headers] || ["TimeCreated","Id","LevelDisplayName","ProviderName","Message"]
  timestamp_fields = opts[:timestamp_fields] || ["TimeCreated","timestamp","time"]
  id_fields        = opts[:id_fields] || ["Id","EventID","Event"]
  level_fields     = opts[:level_fields] || ["LevelDisplayName","Level","Severity"]
  source_fields    = opts[:source_fields] || ["ProviderName","source","Source"]
  message_fields   = opts[:message_fields] || ["Message","MessageText","log_line","log"]

  File.open(out_path, "w") do |out|
    begin
      # best-effort CSV parsing (some files may be malformed -> rescue)
      CSV.foreach(csv_path, headers: true) do |row|
        # safely fetch values from known header names
        ts = nil
        timestamp_fields.each { |f| ts = row[f] if ts.nil? && row && row.headers.include?(f) && row[f] }
        ts ||= row[0] rescue nil

        # parse timestamp to readable form (if possible)
        begin
          ts_readable = ts ? Time.parse(ts.to_s).strftime("%Y-%m-%d %H:%M:%S") : ""
        rescue
          ts_readable = ts.to_s
        end

        level = ""
        level_fields.each { |f| level = row[f].to_s if level.empty? && row && row.headers.include?(f) && row[f] }

        evt_id = ""
        id_fields.each { |f| evt_id = row[f].to_s if evt_id.empty? && row && row.headers.include?(f) && row[f] }

        src = ""
        source_fields.each { |f| src = row[f].to_s if src.empty? && row && row.headers.include?(f) && row[f] }

        msg = ""
        message_fields.each { |f| msg = row[f].to_s if msg.empty? && row && row.headers.include?(f) && row[f] }

        level = level.empty? ? (row["severity"] || "INFO") : level
        src = src.empty? ? File.basename(csv_path) : src
        msg = tidy(msg)

        out.puts "[#{ts_readable}] #{level.ljust(7)} | #{tidy(src,80)} | #{msg}#{evt_id && evt_id.length>0 ? " (EventID: #{evt_id})" : ""}"
      end
    rescue CSV::MalformedCSVError, ArgumentError => e
      # fallback: raw-line processing - works for malformed CSV or raw logs
      File.readlines(csv_path, :encoding => 'bom|utf-8', :invalid => :replace).each_with_index do |line, idx|
        next if idx == 0 && line =~ /timestamp|TimeCreated|timestamp/i  # skip header-ish first line
        line_s = tidy(line)
        next if line_s.empty?
        out.puts "[#{Time.now.strftime("%Y-%m-%d %H:%M:%S")}] INFO    | #{File.basename(csv_path)} | #{line_s}"
      end
    rescue => ex
      out.puts "[#{Time.now.strftime("%Y-%m-%d %H:%M:%S")}] ERROR   | readable_from_csv | Failed to parse #{csv_path}: #{ex}"
    end
  end
end

# walk each category, build a readable text file
def build_readable_reports(rootdir)
  Dir.glob("#{rootdir}/**/*").select { |p| File.file?(p) && File.extname(p).downcase == ".csv" }.each do |csvfile|
    # derive output path: same folder, file readable_<orig>.txt
    folder = File.dirname(csvfile)
    base   = File.basename(csvfile, ".csv")
    outpth = File.join(folder, "readable_#{base}.txt")
    # Special-case Windows Event CSVs to tell the parser expected headers
    if folder =~ /WindowsEvent/i
      readable_from_csv(csvfile, outpth, {
        headers: ["TimeCreated","Id","LevelDisplayName","ProviderName","Message"],
        timestamp_fields: ["TimeCreated"],
        id_fields: ["Id"],
        level_fields: ["LevelDisplayName"],
        source_fields: ["ProviderName"],
        message_fields: ["Message"]
      })
    else
      # generic logs - try generic mapping
      readable_from_csv(csvfile, outpth)
    end
  end
end

# Example call: place this call after extraction and before packaging/zipping
# build_readable_reports(ROOTDIR)

  # Write filtered results
  CSV.open(csv_file, "w") { |csv| rows.each { |r| csv << r } }
end

# === SYSTEM SNAPSHOTS ===
def system_snapshot(root)
  out = File.join(root, "SystemSnapshot")
  FileUtils.mkdir_p(out)

  progress "Capturing system snapshot"

  system("powershell -NoProfile -Command \"Get-CimInstance Win32_LogicalDisk | Export-Csv '#{out}/Disk.csv' -NoTypeInformation\"")
  system("powershell -NoProfile -Command \"Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory | Export-Csv '#{out}/Memory.csv' -NoTypeInformation\"")
  system("powershell -NoProfile -Command \"Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1 -MaxSamples 5 | Export-Csv '#{out}/CPU.csv' -NoTypeInformation\"")
end

# === EXECUTION ===
puts "\n==== Incident Collection Started ====\n"

%w[System Application Security].each do |log|
  collect_windows_events(log, hours, ROOTDIR)
end

collect_logs_from_dir("PostgreSQL", "C:/Program Files/PostgreSQL/13/data/pglog", hours, ROOTDIR)
collect_logs_from_dir("Datadog", "C:/ProgramData/Datadog/logs", hours, ROOTDIR)
collect_logs_from_dir("IMQS", "C:/IMQS/logs", hours, ROOTDIR)

Dir.glob("#{ROOTDIR}/**/*.csv").each do |csv|
  extract_errors(csv, KEYWORDS)
end

system_snapshot(ROOTDIR)

puts "\n✅ Incident package built at:\n#{ROOTDIR}"
puts "Run with: --yesterday  |  --hours 6  |  --today\n\n"
