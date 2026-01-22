#!/usr/bin/env ruby
# TripWire v4.0 - Multi-Strategy Incident Detection
# Windows Events + Sniffer + Vacuum + Configured Paths

require_relative '../lib/version'
require_relative '../lib/config'
require_relative '../lib/logger'
require_relative '../lib/stats'
require_relative '../lib/utils'
require_relative '../lib/tsv'
require_relative '../lib/powershell'
require_relative '../lib/time_parser'
require_relative '../lib/path_resolver'
require_relative '../lib/collectors/signature_learner'
require_relative '../lib/collectors/windows'
require_relative '../lib/collectors/sniffer'
require_relative '../lib/collectors/vacuum'
require_relative '../lib/collectors/files'
require_relative '../lib/analyzers/correlation'
require_relative '../lib/processors/alerts'
require_relative '../lib/processors/snapshot'
require_relative '../lib/cli'

require 'yaml'

module TripWire
  class Runner
    def initialize(options = {})
      @opts = options
      @logger = TripWire::Logger.instance
      @stats  = TripWire::Stats.instance
      
      config_path = File.expand_path('../../config/config.yml', __dir__)
      if File.exist?(config_path)
        begin
          @config = YAML.load_file(config_path)
          
          if @config && @config['options']
            @config['options'].each do |key, value|
              opt_key = key.to_sym
              @opts[opt_key] = value unless @opts.key?(opt_key)
            end
          end
        rescue
          @config = {}
        end
      else
        @config = {}
      end

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
      exit(2)
    end

    private
  
    def setup_directories
      @root = File.join(Dir.pwd, "TripWire_#{Time.now.strftime('%Y%m%d-%H%M%S')}")
      
      @dirs = {
        win: "#{@root}/Windows",
        sniffer: "#{@root}/Sniffer",
        vacuum: "#{@root}/Vacuum",
        files: "#{@root}/ConfiguredLogs",
        analysis: "#{@root}/Analysis",
        alerts: "#{@root}/Alerts",
        snapshot: "#{@root}/Snapshot"
      }
      
      FileUtils.mkdir_p(@root)
      
      TripWire::Logger.setup_debug("#{@root}/debug.log", @opts[:verbose])
    end

    def display_banner
      st, et = TripWire::TimeParser.parse(@opts)
      
      # Build mode description
      modes = []
      modes << 'Windows Events' unless @opts[:skip_windows]
      modes << ' Sniffer' if @opts[:sniffer]
      modes << ' Vacuum' if @opts[:vacuum]
      modes << 'Configured Paths' if @opts[:collect_files] && has_configured_paths?
      modes << ' Analysis' if @opts[:analyze]
      
      mode_str = modes.empty? ? 'Windows Only' : modes.join(' + ')
      
      banner = <<-BANNER

╔══════════════════════════════════════════════════════════════════════╗
║   ████████╗██████╗ ██╗██████╗ ██╗    ██╗██╗██████╗ ███████╗          ║
║   ╚══██╔══╝██╔══██╗██║██╔══██╗██║    ██║██║██╔══██╗██╔════╝          ║
║      ██║   ██████╔╝██║██████╔╝██║ █╗ ██║██║██████╔╝█████╗            ║
║      ██║   ██╔══██╗██║██╔═══╝ ██║███╗██║██║██╔══██╗██╔══╝            ║
║      ██║   ██║  ██║██║██║     ╚███╔███╔╝██║██║  ██║███████╗          ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝          ║
║                                                                      ║
║        Incident Detection System v#{TripWire::VERSION.center(22)}             ║
╚══════════════════════════════════════════════════════════════════════╝

Mode: #{mode_str}
Time: #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}
Output: #{@root}

      BANNER
      
      puts banner
    end
    
    def collect_data
      st, et = TripWire::TimeParser.parse(@opts)
      collectors_run = 0

      if !@opts[:skip_windows] && Gem.win_platform?
        @logger.info " Collecting Windows Events..."
        FileUtils.mkdir_p(@dirs[:win])
        
        TripWire::Collectors::Windows.collect(
          %w[System Application Security], 
          st, et, 
          @dirs[:win], 
          @opts
        )
        collectors_run += 1
      elsif @opts[:skip_windows]
        @logger.info "⏭  Skipping Windows Events (--skip-windows)"
      end

      if @opts[:sniffer]
        @logger.info " Collecting Sniffer Logs (content-based)..."
        FileUtils.mkdir_p(@dirs[:sniffer])
        
        TripWire::Collectors::Sniffer.collect(st, et, @root, @opts)
        collectors_run += 1
      end

      if @opts[:vacuum]
        @logger.info " Collecting Vacuum Logs (path-based)..."
        FileUtils.mkdir_p(@dirs[:vacuum])
        
        TripWire::Collectors::Vacuum.collect(st, et, @root, @opts)
        collectors_run += 1
      end

      if @opts[:collect_files] != false && has_configured_paths?
        @logger.info " Collecting from configured paths..."
        FileUtils.mkdir_p(@dirs[:files])
        
        collect_configured_paths(st, et)
        collectors_run += 1
      end

      if collectors_run == 0
        @logger.warn "  No collection methods enabled!"
        @logger.warn "   Use --sniffer, --vacuum, or configure log paths"
        @logger.warn "   Or run with --all-modes to enable everything"
      end
    end

    def has_configured_paths?
      @config && @config['log_sources'] && !@config['log_sources'].empty?
    end

    def collect_configured_paths(st, et)
      log_sources = @config['log_sources'] || {}
      
      log_sources.each do |name, config|
        path = resolve_log_path(name, config)
        
        if path && Dir.exist?(path)
          @logger.info "   #{name}: #{path}"
          
          TripWire::Collectors::Files.collect(
            name, 
            path, 
            st, et, 
            @dirs[:files], 
            @opts
          )
        else
          @logger.warn "   #{name}: Path not found"
        end
      end
    end

    def resolve_log_path(name, config)
      # Use PathResolver if available, otherwise use configured path directly
      if defined?(TripWire::PathResolver)
        TripWire::PathResolver.resolve(
          name: name,
          configured: config['path'],
          defaults: config['default_paths'] || [],
          search_names: config['search_names'] || [name]
        )
      else
        config['path']
      end
    end

    def process_data
      st, et = TripWire::TimeParser.parse(@opts)
      
      @logger.info " Scanning for alerts..."
      TripWire::Processors::Alerts.extract(@root, st, et, @dirs[:alerts])
      
      if @opts[:analyze]
        @logger.info " Running correlation analysis..."
        TripWire::Analyzers::Correlation.analyze(@root, st, et, @opts)
      end
      
      if !@opts[:skip_snapshot] && Gem.win_platform?
        @logger.info " Capturing system snapshot..."
        FileUtils.mkdir_p(@dirs[:snapshot])
        TripWire::Processors::Snapshot.capture(@dirs[:snapshot])
      end
    end

    def write_summary
      elapsed = Time.now - @stats[:start]
      st, et = TripWire::TimeParser.parse(@opts)
      
      # Build collection summary
      collection_summary = []
      collection_summary << "Windows Events: #{@stats[:lines]} events" if @stats[:lines] > 0
      collection_summary << "Vacuum Sources: #{@stats[:vacuum_sources]} (#{@stats[:vacuum_files]} files, #{@stats[:vacuum_lines]} lines)" if @stats[:vacuum_sources] > 0
      collection_summary << "Sniffer Sources: #{@stats[:sniffer_sources]} (#{@stats[:sniffer_files]} files, #{@stats[:sniffer_lines]} lines)" if @stats[:sniffer_sources] > 0
      collection_summary << "Configured Paths: #{@stats[:files]} files" if @stats[:files] > 0
      collection_summary << "Alerts: #{@stats[:alerts]} critical issues" if @stats[:alerts] > 0
      
      sum = <<-SUM
═══════════════════════════════════════════════════════════════════
TripWire v#{TripWire::VERSION} - Summary
═══════════════════════════════════════════════════════════════════
Duration: #{sprintf('%.2f', elapsed)}s
Range: #{st.strftime('%Y-%m-%d %H:%M')} → #{et.strftime('%Y-%m-%d %H:%M')}

#{collection_summary.empty? ? "⚠️  No data collected" : collection_summary.join("\n")}

Output: #{@root}

Key Files:
  - debug.log (detailed execution log)
#{@opts[:vacuum] && @stats[:vacuum_sources] > 0 ? "  - Vacuum/INVENTORY.txt" : ""}
#{@opts[:sniffer] && @stats[:sniffer_sources] > 0 ? "  - Sniffer/DISCOVERY_REPORT.txt" : ""}
#{@opts[:analyze] ? "  - Analysis/INCIDENT_ANALYSIS.txt" : ""}
#{@stats[:alerts] > 0 ? "  - Alerts/ (critical issues)" : ""}

#{collection_summary.empty? ? "💡 Tip: Try running with --all-modes to enable all collectors" : ""}
═══════════════════════════════════════════════════════════════════
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