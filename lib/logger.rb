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
    
    def self.setup_debug(path, verbose = false)
      @@debug = ::Logger.new(path)
      @@debug.level = verbose ? ::Logger::DEBUG : ::Logger::INFO
      @@debug.formatter = proc { |sev, time, _, msg| "[#{time.strftime('%H:%M:%S')}] [#{sev}] #{msg}\n" }
    end
    
    def self.summary
      @@summary ||= ::Logger.new(STDOUT)
    end
    
    %i[debug info warn error fatal].each do |level|
      define_method(level) { |msg| @logger.send(level, msg) }
    end
    
    def log_enter(module_name, method_name, params = {})
      if @logger.level <= ::Logger::DEBUG
        param_str = params.empty? ? '' : " | #{params.inspect}"
        @logger.debug("[#{module_name}] >> #{method_name}#{param_str}")
      end
    end
    
    def log_exit(module_name, method_name, result = nil)
      if @logger.level <= ::Logger::DEBUG
        result_str = result.nil? ? '' : " | #{result.inspect}"
        @logger.debug("[#{module_name}] << #{method_name}#{result_str}")
      end
    end
    
    def debug_log(module_name, message)
      if @logger.level <= ::Logger::DEBUG
        @logger.debug("[#{module_name}] #{message}")
      end
    end
    
    def log_file_op(operation, path, details = {})
      if @logger.level <= ::Logger::DEBUG
        detail_str = details.empty? ? '' : " | #{details.inspect}"
        @logger.debug("[FILE] #{operation}: #{path}#{detail_str}")
      end
    end
    
    def log_state(label, state = {})
      if @logger.level <= ::Logger::DEBUG
        state_str = state.empty? ? '' : " | #{state.inspect}"
        @logger.debug("[#{label}]#{state_str}")
      end
    end
    
    def log_powershell(script, success, details = {})
      if @logger.level <= ::Logger::DEBUG
        status = success ? 'SUCCESS' : 'FAILURE'
        detail_str = details.empty? ? '' : " | #{details.inspect}"
        @logger.debug("[PWSH] #{status}#{detail_str}")
      end
    end
    
    def log_path_resolution(event, message = '')
      if @logger.level <= ::Logger::DEBUG
        msg_str = message.empty? ? '' : " | #{message}"
        @logger.debug("[PATH] #{event}#{msg_str}")
      end
    end
    
    def log_alert_check(matched, keywords, message, status)
      if @logger.level <= ::Logger::DEBUG
        msg_preview = message[0...100]
        @logger.debug("[ALERT] matched=#{matched}, keywords=#{keywords}, status=#{status}, msg=#{msg_preview}")
      end
    end
  end
end