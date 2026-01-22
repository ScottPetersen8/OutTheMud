module TripWire
  module Processors
    module Alerts
      KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
      
      def self.extract(root, st, et, out_dir)
        log = TripWire::Logger.instance
        log.info "Scanning for alerts..."
        
        pattern = Regexp.union(KEYWORDS.map { |k| /\b#{k}\b/i })
        tsvs = Dir.glob(File.join(root, '**', '*.tsv')).reject { |f| f.include?('/Alerts/') || f.include?('\\Alerts\\') }
        
        if tsvs.empty?
          log.warn "No TSV files found"
          return
        end
        
        total = 0
        tsvs.each do |tsv|
          begin
            total += scan_file(tsv, pattern, st, et, out_dir)
          rescue => e
            log.error "Failed #{File.basename(tsv)}: #{e.message}"
          end
        end
        
        if total > 0
          log.info "  ✓ #{total} alerts extracted"
        else
          log.info "  No alerts found (no critical keywords matched)"
          FileUtils.rm_rf(out_dir) if Dir.exist?(out_dir) && Dir.empty?(out_dir)
        end
      end
      
      private
      
      def self.scan_file(tsv, pattern, st, et, out_dir)
        alerts = [%w[timestamp severity message source]]
        
        TripWire::TSV.each(tsv) do |row|
          msg = row['Message'] || row['message'] || row['log_line'] || row.values.join(' ')
          
          if msg =~ pattern
            raw_ts = row['TimeCreated'] || row['timestamp'] || row.values.first
            ts = parse_ts(raw_ts)
            
            if ts && ts >= st && ts <= et
              alerts << [ts.strftime('%Y-%m-%d %H:%M:%S'), 'ALERT', msg[0...2000], File.basename(tsv)]
              TripWire::Stats.instance.increment(:alerts)
            end
          end
        end
        
        count = alerts.size - 1
        
        if count > 0
          FileUtils.mkdir_p(out_dir)
          out_file = File.join(out_dir, "alerts_#{File.basename(tsv)}")
          TripWire::TSV.write(out_file, alerts)
          TripWire::Logger.instance.info "   #{count} → #{File.basename(out_file)}"
        end
        
        count
      end
      
      def self.parse_ts(raw)
        s = raw.to_s.strip
        return nil if s.empty? || s =~ /^(Exception|Error|Warning)/i
        
        formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%m/%Y %H:%M:%S']
        
        formats.each do |fmt|
          return Time.strptime(s, fmt) rescue next
        end
        
        require 'time'
        Time.parse(s) rescue nil
      end
    end
  end
end