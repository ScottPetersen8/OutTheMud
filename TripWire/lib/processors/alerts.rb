module TripWire
  module Processors
    module Alerts
      KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
      
      def self.extract(root, st, et, out_dir)
        log = TripWire::Logger.instance
        log.info "Scanning for alerts..."
        
        FileUtils.mkdir_p(out_dir)
        pattern = Regexp.union(KEYWORDS.map { |k| /\b#{k}\b/i })
        
        tsvs = Dir.glob(File.join(root, '**', '*.tsv')).reject { |f| f.include?('/Alerts/') || f.include?('\\Alerts\\') }
        return log.warn "No TSV files found" if tsvs.empty?
        
        total = 0
        tsvs.each do |tsv|
          count = scan_file(tsv, pattern, st, et, out_dir)
          total += count
        rescue => e
          log.error "Failed #{File.basename(tsv)}: #{e.message}"
        end
        
        log.info "  ✓ #{total} alerts extracted"
      end
      
      private
      
      def self.scan_file(tsv, pattern, st, et, out_dir)
        log = TripWire::Logger.instance
        alerts = [%w[timestamp severity message source]]
        rows = 0
        matches = 0
        bad_ts = 0
        out_of_range = 0
        sample_ts = nil
        
        TripWire::TSV.each(tsv) do |row|
          rows += 1
          
          msg = row['Message'] || row['message'] || row['log_line'] || row.values.join(' ')
          
          if msg.match?(pattern)
            matches += 1
            
            raw_ts = row['TimeCreated'] || row['timestamp'] || row.values.first
            ts = parse_ts(raw_ts)
            
            # Capture first timestamp for debugging
            sample_ts ||= raw_ts if matches == 1
            
            if ts.nil?
              bad_ts += 1
            elsif ts < st || ts > et
              out_of_range += 1
            else
              alerts << [ts.strftime('%Y-%m-%d %H:%M:%S'), 'ALERT', msg[0...2000], File.basename(tsv)]
              TripWire::Stats.instance.increment(:alerts)
            end
          end
        end
        
        count = alerts.size - 1
        
        if count > 0
          out_file = File.join(out_dir, "alerts_#{File.basename(tsv)}")
          TripWire::TSV.write(out_file, alerts)
          log.info "   #{count} → #{File.basename(out_file)}"
        elsif matches > 0
          log.info "  #{File.basename(tsv)}: #{matches} matches, bad_ts=#{bad_ts}, out_of_range=#{out_of_range}"
          log.info "    Sample timestamp: #{sample_ts.inspect}" if sample_ts
          log.info "    Expected range: #{st} to #{et}"
        end
        
        count
      end
      
      def self.parse_ts(raw)
        s = raw.to_s.strip
        return nil if s.empty? || s =~ /^(Exception|Error|Warning)/i
        
        # Try common formats
        [
          '%Y-%m-%d %H:%M:%S',
          '%Y-%m-%dT%H:%M:%S',
          '%d/%m/%Y %H:%M:%S'
        ].each do |fmt|
          return Time.strptime(s, fmt) rescue next
        end
        
        # Fallback with full timestamp parsing
        require 'time'
        Time.parse(s) rescue nil
      end
    end
  end
end