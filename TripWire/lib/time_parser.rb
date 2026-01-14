require 'date'

module TripWire
  module TimeParser
    def self.parse(opts)
      now = Time.now
      
      case opts[:mode]
      when :today
        mid = Time.new(now.year, now.month, now.day, 0, 0, 0)
        st, et = mid, mid + 86399
      when :yesterday
        mid = Time.new(now.year, now.month, now.day, 0, 0, 0)
        st, et = mid - 86400, mid - 1
      when :last
        st, et = parse_last(opts[:dur], now)
      when :back
        st, et = parse_back(opts[:dur], now)
      else
        st, et = now - 86400, now
      end
      
      # DEBUG LINE
      puts "DEBUG: Time range: #{st} to #{et} (#{((et - st) / 3600).round(2)} hours)"
      
      [st, et]
    end
    
    private
    
    def self.parse_last(dur, now)
      if dur =~ /^(\d+)([hdwm])$/i
        sec = { 'h' => 3600, 'd' => 86400, 'w' => 604800, 'm' => 2592000 }[$2.downcase] * $1.to_i
        [now - sec, now]
      else
        raise ArgumentError, "Invalid --last (use: 6h, 2d, 1w, 1m)"
      end
    end
    
    def self.parse_back(dur, now)
      m = w = d = h = 0
      dur.to_s.scan(/(\d+)([mwdh])/i).each { |n, u| eval("#{u.downcase} = #{n.to_i}") }
      dt = now.to_datetime << m
      dt -= (w * 7 + d + Rational(h, 24))
      t = dt.to_time
      [t, t + 86399]
    end
  end
end