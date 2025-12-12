require 'singleton'

module TripWire
  class Stats
    include Singleton
    
    def initialize
      @data = Hash.new(0)
      @data[:start] = Time.now
    end
    
    def increment(key, val = 1)
      @data[key] += val
    end
    
    def [](key)
      @data[key]
    end
    
    def to_h
      @data
    end
  end
end