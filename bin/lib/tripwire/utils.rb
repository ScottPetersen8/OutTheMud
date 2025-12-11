module TripWire
  module Utils
    def self.clean(str, max = 1000)
      str.to_s.encode('UTF-8', invalid: :replace, undef: :replace)
        .gsub(/[\r\n\t]+/, ' ').strip[0...max]
    rescue
      ''
    end
    
    def self.parse_timestamp(line)
      [/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/, /(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})/].each do |pat|
        return Time.parse($1) if line&.match(pat)
      rescue
        next
      end
      nil
    end
    
    def self.severity(line)
      case line.to_s
      when /\b(ERROR|FATAL|CRITICAL)\b/i then 'ERROR'
      when /\b(WARN|WARNING)\b/i then 'WARN'
      else 'INFO'
      end
    end
    
    def self.spinner(msg)
      return -> {} if TripWire::Logger.instance.level == ::Logger::DEBUG
      
      frames, idx, running = %w[⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏], 0, true
      t = Thread.new { while running; print "\r#{frames[idx]} #{msg}..."; idx = (idx + 1) % frames.size; sleep 0.1; end }
      -> { running = false; t.join; print "\r#{' ' * (msg.size + 20)}\r" }
    end
  end
end