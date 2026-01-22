require 'optparse'

module TripWire
  module CLI
    def self.parse(args)
      opts = {
        mode: :default,
        dur: '24h',
        verbose: false,
        all_files: false,
        skip_windows: false,
        skip_snapshot: false,
        all_sec: false,
        all_lvl: false,
        parallel: false,
        
        # Collection modes
        sniffer: false,
        vacuum: false,
        
        # Sniffer options
        sniffer_deep: false,
        sniffer_max_files: 10000,
        sniffer_sample_lines: 50,
        sniffer_paths: nil,
        
        # Vacuum options
        vacuum_deep: false,
        vacuum_max_generic: 100,
        vacuum_paths: nil,
        
        # Analysis
        analyze: false,
        
        # File-based collection (for configured paths)
        collect_files: true
      }
      
      OptionParser.new do |o|
        o.banner = "TripWire v#{TripWire::VERSION} - Advanced Log Collection & Analysis\n\n" +
                   "Usage: ruby tripwire.rb [options]\n\n" +
                   "COLLECTION MODES:\n" +
                   "  By default, only Windows Events are collected.\n" +
                   "  Use --sniffer or --vacuum to discover other logs:\n\n" +
                   "  --sniffer     Content-based discovery (smart, slower)\n" +
                   "  --vacuum      Path-based discovery (fast, known apps)\n" +
                   "  --all-modes   Enable both Sniffer and Vacuum\n"
        
        o.separator ""
        o.separator "Collection Modes:"
        o.on('--sniffer', 'Content-based log discovery') { opts[:sniffer] = true }
        o.on('--vacuum', 'Path-based log discovery') { opts[:vacuum] = true }
        o.on('--all-modes', 'Enable Sniffer + Vacuum + Windows') do
          opts[:sniffer] = true
          opts[:vacuum] = true
        end
        o.on('--files-only', 'Only collect from configured file paths') do
          opts[:skip_windows] = true
          opts[:sniffer] = false
          opts[:vacuum] = false
        end
        
        o.separator ""
        o.separator "Time Range:"
        o.on('--last D', 'Duration (6h, 2d, 1w, 1m)') { |d| opts[:mode] = :last; opts[:dur] = d }
        o.on('--back D', 'Offset (2m1w3d)') { |d| opts[:mode] = :back; opts[:dur] = d }
        o.on('--today', 'Today\'s logs') { opts[:mode] = :today }
        o.on('--yesterday', 'Yesterday\'s logs') { opts[:mode] = :yesterday }
        
        o.separator ""
        o.separator "Sniffer Options:"
        o.on('--sniffer-deep', 'Deep scan (8 levels, slower)') { opts[:sniffer_deep] = true }
        o.on('--sniffer-max N', Integer, 'Max files to scan (default: 10000)') { |n| opts[:sniffer_max_files] = n }
        o.on('--sniffer-sample N', Integer, 'Lines to sample per file (default: 50)') { |n| opts[:sniffer_sample_lines] = n }
        o.on('--sniffer-paths P1,P2', Array, 'Specific paths to scan (comma-separated)') { |p| opts[:sniffer_paths] = p }
        
        o.separator ""
        o.separator "Vacuum Options:"
        o.on('--vacuum-deep', 'Deep directory search (6 levels vs 3)') { opts[:vacuum_deep] = true }
        o.on('--vacuum-max N', Integer, 'Max generic log files (default: 100)') { |n| opts[:vacuum_max_generic] = n }
        o.on('--vacuum-paths P1,P2', Array, 'Specific paths to search (comma-separated)') { |p| opts[:vacuum_paths] = p }
        
        o.separator ""
        o.separator "Analysis:"
        o.on('--analyze', 'Run root cause analysis after collection') { opts[:analyze] = true }
        
        o.separator ""
        o.separator "Windows Events:"
        o.on('--skip-windows', 'Skip Windows event collection') { opts[:skip_windows] = true }
        o.on('--all-security', 'All Security events (not just filtered IDs)') { opts[:all_sec] = true }
        o.on('--all-levels', 'All event levels (not just Error/Warning/Info)') { opts[:all_lvl] = true }
        o.on('--parallel', 'Parallel Windows event collection') { opts[:parallel] = true }
        
        o.separator ""
        o.separator "Other Options:"
        o.on('--skip-snapshot', 'Skip system snapshot') { opts[:skip_snapshot] = true }
        o.on('--all-files', 'Include all files (ignore mtime filtering)') { opts[:all_files] = true }
        o.on('--verbose', 'Debug logging') { opts[:verbose] = true }
        o.on('-h', '--help', 'Show this help') { puts o; exit }
        o.on('--version', 'Show version') { puts "TripWire v#{TripWire::VERSION}"; exit }
        
        o.separator ""
        o.separator "Examples:"
        o.separator "  # Basic Windows events only (default)"
        o.separator "  ruby tripwire.rb --last 24h"
        o.separator ""
        o.separator "  # Discover all logs on system"
        o.separator "  ruby tripwire.rb --all-modes --last 6h"
        o.separator ""
        o.separator "  # Deep content discovery with analysis"
        o.separator "  ruby tripwire.rb --sniffer --sniffer-deep --analyze --last 12h"
        o.separator ""
        o.separator "  # Fast path-based discovery"
        o.separator "  ruby tripwire.rb --vacuum --last 1d"
        o.separator ""
        o.separator "  # Scan specific directories only"
        o.separator "  ruby tripwire.rb --sniffer --sniffer-paths 'C:/inetpub,C:/ProgramData/MyApp'"
      end.parse!(args)
      
      opts
    end
  end
end