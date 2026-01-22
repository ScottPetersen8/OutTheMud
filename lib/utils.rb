module TripWire
  module Utils
    def self.clean(str, max = 1000)
      result = str.to_s.encode('UTF-8', invalid: :replace, undef: :replace)
        .gsub(/[\r\n\t]+/, ' ').strip[0...max]
      result
    rescue => e
      TripWire::Logger.instance.debug_log('UTILS', "clean() error: #{e.message}")
      ''
    end
    
    def self.parse_timestamp(line)
      log = TripWire::Logger.instance
      
      patterns = [
        {regex: /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/, name: 'ISO8601'},
        {regex: /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})/, name: 'syslog'}
      ]
      
      patterns.each do |pat|
        begin
          if line && line.match(pat[:regex])
            ts = Time.parse($1)
            log.log_timestamp_parse(line, ts, pat[:name])
            return ts
          end
        rescue => e
          log.debug_log('TIMESTAMP', "Parse failed with #{pat[:name]}: #{e.message}")
          next
        end
      end
      
      log.log_timestamp_parse(line, nil)
      nil
    end
    
    def self.severity(line)
      str = line.to_s
      result = case str
      when /\b(ERROR|FATAL|CRITICAL)\b/i then 'ERROR'
      when /\b(WARN|WARNING)\b/i then 'WARN'
      else 'INFO'
      end
      
      TripWire::Logger.instance.debug_log('SEVERITY', "Detected: #{result} | Line: #{str[0...100]}")
      result
    end
    
    def self.spinner(msg)
      return -> {} if TripWire::Logger.instance.level == ::Logger::DEBUG
      
      frames, idx, running = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏], 0, true
      t = Thread.new { while running; print "\r#{frames[idx]} #{msg}..."; idx = (idx + 1) % frames.size; sleep 0.1; end }
      -> { running = false; t.join; print "\r#{' ' * (msg.size + 20)}\r" }
    end
  end
end