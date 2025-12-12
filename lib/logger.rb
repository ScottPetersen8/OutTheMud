require 'logger'
require 'singleton'

module TripWire
  class Logger
    include Singleton
    
    attr_accessor :level
    
    def initialize
      @logger = ::Logger.new(STDOUT)
      @logger.level = ::Logger::INFO
      @logger.formatter = proc { |sev, time, _, msg| "[#{time.strftime('%H:%M:%S')}] #{msg}\n" }
    end
    
    def self.setup_summary(path)
      @@summary = ::Logger.new(path)
      @@summary.formatter = proc { |_, _, _, m| "#{m}\n" }
    end
    
    def self.summary
      @@summary ||= ::Logger.new(STDOUT)
    end
    
    %i[debug info warn error fatal].each do |level|
      define_method(level) { |msg| @logger.send(level, msg) }
    end
  end
end