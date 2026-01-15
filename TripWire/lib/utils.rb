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
      mutex = Mutex.new
      
      t = Thread.new do
        while mutex.synchronize { running }
          begin
            print "\r#{frames[idx]} #{msg}..."
            idx = (idx + 1) % frames.size
            sleep 0.1
          rescue IOError, Errno::EBADF
            # Stream closed, exit gracefully
            break
          end
        end
      end
      
      -> do
        mutex.synchronize { running = false }
        t.join(1) # Wait max 1 second
        t.kill if t.alive? # Force kill if still running
        begin
          print "\r#{' ' * (msg.size + 20)}\r"
        rescue IOError, Errno::EBADF
          # Ignore if output stream is closed
        end
      end
    end
  end
end