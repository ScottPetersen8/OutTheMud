#!/usr/bin/env ruby
# TripWire v3.2 - Modular Incident Detection System
# Main entry point

require_relative '../lib/version'
require_relative '../lib/path_resolver'
require_relative '../lib/config'
require_relative '../lib/logger'
require_relative '../lib/stats'
require_relative '../lib/utils'
require_relative '../lib/tsv'
require_relative '../lib/powershell'
require_relative '../lib/time_parser'
require_relative '../lib/collectors/windows'
require_relative '../lib/collectors/files'
require_relative '../lib/processors/alerts'
require_relative '../lib/processors/reports'
require_relative '../lib/processors/snapshot'
require_relative '../lib/cli'

require 'yaml'

module TripWire
  class Runner
    def initialize(options = {})
      # Store CLI options
      @opts = options
      
      # Load YAML config
      script_dir = File.dirname(File.expand_path(__FILE__))
      config_path = File.join(script_dir, '..', 'config', 'config.yml')
      if File.exist?(config_path)
        begin
          config = YAML.load_file(config_path)
          
          # Merge paths from config
          if config && config['paths']
            @opts[:paths] ||= {}
            config['paths'].each { |k, v| @opts[:paths][k.to_sym] = v }
          end
          
          # Merge default options (CLI options override config)
          if config && config['options']
            config['options'].each do |key, value|
              opt_key = key.to_sym
              @opts[opt_key] = value unless @opts.key?(opt_key)
            end
          end
          
          # Store other config sections
          @config = config
          
        rescue => e
          warn "[TripWire] Error loading config.yml: #{e.message}"
          @config = {}
        end
      else
        warn "[TripWire] No config.yml found at #{config_path}, using defaults"
        @opts[:paths] ||= {}
        @config = {}
      end

      @logger = TripWire::Logger.instance
      @stats  = TripWire::Stats.instance

      @logger.info "TripWire v#{TripWire::VERSION} initialized"
    end

    def run
      setup_directories
      display_banner
      collect_data
      process_data
      write_summary
      
      @logger.info "✅ Complete!"
    rescue => e
      @logger.fatal "Fatal: #{e.message}"
      @logger.debug e.backtrace.join("\n") if @opts[:verbose]
      exit(2)
    end

    private
  
    def setup_directories
      @root = File.join(Dir.pwd, "TripWire_#{Time.now.strftime('%Y%m%d-%H%M%S')}")
      @dirs = {
        win: "#{@root}/Windows",
        datadog: "#{@root}/Datadog", 
        postgres: "#{@root}/PostgreSQL",
        alerts: "#{@root}/Alerts",
        reports: "#{@root}/Reports",
        snapshot: "#{@root}/Snapshot"
      }
      @dirs.values.each { |d| FileUtils.mkdir_p(d) }
      @dirs.each do |key, dir|
        @logger.debug "Directory for #{key}: #{dir}"
      end
      TripWire::Logger.setup_summary("#{@root}/summary.log")
    end

    def display_banner
      st, et = TripWire::TimeParser.parse(@opts)
      
      puts <<~BANNER

        ╔══════════════════════════════════════════════════════════════════════╗
        ║   ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗          ║
        ║   ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝          ║
        ║      ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗            ║
        ║      ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝            ║
        ║      ██║   ██║  ██║██║██║     ╚███╔╝██╔╝██║██║  ██║███████╗          ║
        ║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝          ║
        ║                                                                      ║
        ║            Incident Detection System v#{TripWire::VERSION.center(22)}         ║
        ╚══════════════════════════════════════════════════════════════════════╝

        Time: #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}
        Output: #{@root}

      BANNER
    end
    
    def collect_data
      st, et = TripWire::TimeParser.parse(@opts)

      # Windows events
      if !@opts[:skip_windows] && !@opts[:skip_win] && Gem.win_platform?
        TripWire::Collectors::Windows.collect(%w[System Application Security], st, et, @dirs[:win], @opts)
      end

      # File logs
      @logger.debug "Starting file log collection..."
      @logger.debug "Options paths: #{@opts[:paths].inspect}"

      configured_datadog = @opts.dig(:paths, :datadog)
      @logger.debug "Configured datadog path: #{configured_datadog.inspect}"
      
      datadog_path = TripWire::PathResolver.resolve(
        name: 'datadog',
        configured: configured_datadog.is_a?(String) ? configured_datadog : nil,
        defaults: TripWire::PathResolver.windows? ?
                    ['C:/ProgramData/Datadog/logs', 'C:/Datadog/logs', 'D:/Datadog/logs'] :
                    ['/var/log/datadog', '/opt/datadog/logs', '/usr/local/var/datadog/logs'],
        search_names: ['datadog', 'dd', 'dd-agent', 'datadog-agent', 'datadog-logs']
      )

      configured_postgres = @opts.dig(:paths, :postgresql)
      @logger.debug "Configured postgres path: #{configured_postgres.inspect}"
      
      postgres_path = TripWire::PathResolver.resolve(
        name: 'postgresql',
        configured: configured_postgres.is_a?(String) ? configured_postgres : nil,
        defaults: TripWire::PathResolver.windows? ?
                    ['C:/Program Files/PostgreSQL', 'C:/PostgreSQL/logs', 'D:/PostgreSQL/logs'] :
                    ['/var/lib/postgresql', '/var/log/postgresql', '/opt/postgresql', '/usr/local/var/log/postgresql'],
        search_names: ['postgresql', 'pgsql', 'pg', 'pg_logs', 'log', 'logs']
      )

      if datadog_path
        @logger.info "Datadog..."
        stop_spinner = TripWire::Utils.spinner("Datadog")
        @opts[:skip_log] = true
        TripWire::Collectors::Files.collect('Datadog', datadog_path, st, et, @dirs[:datadog], @opts)
        @opts[:skip_log] = false
        stop_spinner.call
      end
      
      if postgres_path
        @logger.info "PostgreSQL..."
        stop_spinner = TripWire::Utils.spinner("PostgreSQL")
        @opts[:skip_log] = true
        TripWire::Collectors::Files.collect('PostgreSQL', postgres_path, st, et, @dirs[:postgres], @opts)
        @opts[:skip_log] = false
        stop_spinner.call
      end

      unless datadog_path
        @logger.warn "Datadog path not resolved; writing empty TSV"
        TripWire::TSV.write(File.join(@dirs[:datadog], 'Datadog.tsv'), [%w[timestamp severity message source]])
      end

      unless postgres_path
        @logger.warn "PostgreSQL path not resolved; writing empty TSV"
        TripWire::TSV.write(File.join(@dirs[:postgres], 'PostgreSQL.tsv'), [%w[timestamp severity message source]])
      end
    end

    def process_data
      st, et = TripWire::TimeParser.parse(@opts)
      
      TripWire::Processors::Alerts.extract(@root, st, et, @dirs[:alerts])
      TripWire::Processors::Reports.generate(@root, @dirs[:reports])
      TripWire::Processors::Snapshot.capture(@dirs[:snapshot]) if !@opts[:skip_snapshot] && !@opts[:skip_snap] && Gem.win_platform?
    end

    def write_summary
      elapsed = Time.now - @stats[:start]
      st, et = TripWire::TimeParser.parse(@opts)
      
      sum = <<~SUM
        ═════════════════════════════════════════════════════════════════
        TripWire v#{TripWire::VERSION} - Summary
        ═════════════════════════════════════════════════════════════════
        Duration: #{sprintf('%.2f', elapsed)}s
        Range: #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}
        Files: #{@stats[:files]} | Lines: #{@stats[:lines]} | Errors: #{@stats[:err]} | Alerts: #{@stats[:alerts]}
        Output: #{@root}
        ═════════════════════════════════════════════════════════════════
      SUM
      
      File.write("#{@root}/SUMMARY.txt", sum)
      puts "\n#{sum}\n"
    end
  end
end

# Entry point
if __FILE__ == $0
  trap('INT') { puts "\n⚠️  Interrupted"; exit(130) }
  
  options = TripWire::CLI.parse(ARGV)
  TripWire::Logger.instance.level = Logger::DEBUG if options[:verbose]
  
  runner = TripWire::Runner.new(options)
  runner.run
end