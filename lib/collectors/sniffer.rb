# lib/collectors/sniffer.rb
# Content-based log discovery for specific log types

module TripWire
  module Collectors
    module Sniffer
      # Target log signatures (expandable)
      LOG_SIGNATURES = {
        'Datadog_Agent' => {
          patterns: [/Datadog Agent.*starting/i, /dogstatsd.*starting/i, /dd-agent/i, /datadog/i],
          priority: :high,
          paths: ['C:/ProgramData/Datadog', 'C:/Program Files/Datadog', '/var/log/datadog', '/opt/datadog']
        },
        'PostgreSQL' => {
          patterns: [/database system .* ready to accept/i, /FATAL:\s+/i, /postgres\[\d+\]/, /PostgreSQL/i],
          priority: :high,
          paths: ['C:/Program Files/PostgreSQL', 'C:/ProgramData/PostgreSQL', '/var/log/postgresql', '/var/lib/postgresql']
        }
        # Add more log types here as needed
      }.freeze
      
      SKIP_DIRS = ['WinSxS', 'Installer', 'assembly', '$Recycle.Bin', 'node_modules', '.git', 'System32', 'SysWOW64'].freeze
      
      def self.collect(st, et, root_dir, opts)
        log = TripWire::Logger.instance
        sniffer_dir = File.join(root_dir, 'Sniffer')
        FileUtils.mkdir_p(sniffer_dir)
        
        # Collect each log type individually (like Windows events)
        LOG_SIGNATURES.each do |log_type, config|
          collect_log_type(log_type, config, st, et, sniffer_dir, opts)
        end
      end
      
      private
      
      def self.collect_log_type(log_type, config, st, et, sniffer_dir, opts)
        log = TripWire::Logger.instance
        log.info "#{log_type}..."
        
        stop_spinner = TripWire::Utils.spinner(log_type)
        
        # Find log files for this type
        log_files = find_logs_for_type(config)
        
        if log_files.empty?
          stop_spinner.call
          log.info "  ✗ Not found"
          # Still create empty TSV so you know we checked
          create_empty_tsv(sniffer_dir, log_type)
          return
        end
        
        # Consolidate all files into ONE TSV
        rows = [%w[timestamp severity message source file_path]]
        
        log_files.each do |file_path|
          file_rows = parse_log_file(file_path, st, et)
          rows.concat(file_rows)
        end
        
        # Write single consolidated TSV
        tsv_path = File.join(sniffer_dir, "#{log_type}.tsv")
        TripWire::TSV.write(tsv_path, rows)
        
        total_lines = rows.size - 1
        stop_spinner.call
        log.info "  ✓ #{log_files.size} files, #{total_lines} lines"
        
        TripWire::Stats.instance.increment(:files, log_files.size)
        TripWire::Stats.instance.increment(:lines, total_lines)
        
      rescue => e
        stop_spinner.call if stop_spinner
        log.error "#{log_type}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end
      
      def self.find_logs_for_type(config)
        found = []
        
        # Search in known paths first
        config[:paths].each do |path|
          next unless Dir.exist?(path)
          
          Dir.glob(File.join(path, '**', '*')).each do |file|
            next unless File.file?(file) && looks_like_log_file?(file)
            
            # Verify content matches patterns
            if matches_patterns?(file, config[:patterns])
              found << file
            end
          end
        end
        
        found.uniq
      end
      
      def self.matches_patterns?(file, patterns)
        return false if File.size(file) > 500_000_000
        
        sample = read_file_sample(file, 50)
        return false if sample.empty?
        
        patterns.any? { |pattern| sample =~ pattern }
      rescue
        false
      end
      
      def self.parse_log_file(file_path, st, et)
        rows = []
        
        begin
          mt = File.mtime(file_path)
          
          File.open(file_path, 'r:bom|utf-8') do |f|
            f.each_line do |line|
              next if line.strip.empty?
              
              # Extract timestamp, severity, message
              parsed = parse_log_line(line, file_path)
              ts = parsed && parsed[:timestamp] ? parsed[:timestamp] : mt
              
              next unless ts.between?(st, et)
              
              rows << [
                ts.strftime('%Y-%m-%d %H:%M:%S'),
                parsed&.[](:severity) || 'INFO',
                TripWire::Utils.clean(parsed&.[](:message) || line.strip),
                File.basename(file_path),
                file_path
              ]
            end
          end
        rescue => e
          TripWire::Logger.instance.debug_log('SNIFFER', "Error processing #{file_path}: #{e.message}")
        end
        
        rows
      end
      
      def self.create_empty_tsv(sniffer_dir, log_type)
        tsv_path = File.join(sniffer_dir, "#{log_type}.tsv")
        TripWire::TSV.write(tsv_path, [%w[timestamp severity message source file_path]])
      end
      
      def self.parse_log_line(line, source)
        # Try to extract timestamp and severity
        timestamp = nil
        severity = nil
        message = line.strip
        
        # Common timestamp patterns
        if line =~ /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)/
          timestamp = Time.parse($1) rescue nil
        elsif line =~ /(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/
          timestamp = Time.parse($1) rescue nil
        end
        
        # Extract severity
        severity = TripWire::Utils.detect_severity(line)
        
        { timestamp: timestamp, severity: severity, message: message }
      rescue
        nil
      end
      
      def self.looks_like_log_file?(path)
        name = File.basename(path).downcase
        name.end_with?('.log', '.txt') || name.include?('log')
      end
      
      def self.read_file_sample(file_path, max_lines)
        sample = []
        File.open(file_path, 'r:bom|utf-8') do |f|
          max_lines.times { line = f.gets; break unless line; sample << line }
        end
        sample.join("\n")
      rescue
        ""
      end
    end
  end
end
