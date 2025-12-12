require 'optparse'

module TripWire
  module CLI
    def self.parse(args)
      opts = {
        mode: :default,
        dur: '24h',
        verbose: false,
        all_files: false,
        skip_win: false,
        skip_snap: false,
        parallel: false,
        all_sec: false,
        all_lvl: false,
        paths: TripWire::Config::DEFAULT_LOG_PATHS.dup
      }
      
      OptionParser.new do |o|
        o.banner = "TripWire v#{TripWire::VERSION}\n\nUsage: ruby tripwire.rb [options]"
        o.on('--last D', 'Duration (6h, 2d, 1w, 1m)') { |d| opts[:mode] = :last; opts[:dur] = d }
        o.on('--back D', 'Offset (2m1w3d)') { |d| opts[:mode] = :back; opts[:dur] = d }
        o.on('--today') { opts[:mode] = :today }
        o.on('--yesterday') { opts[:mode] = :yesterday }
        o.on('--verbose') { opts[:verbose] = true }
        o.on('--skip-windows') { opts[:skip_win] = true }
        o.on('--skip-snapshot') { opts[:skip_snap] = true }
        o.on('--parallel') { opts[:parallel] = true }
        o.on('--all-security') { opts[:all_sec] = true }
        o.on('--all-levels') { opts[:all_lvl] = true }
        o.on('--datadog P') { |p| opts[:paths][:datadog] = p }
        o.on('--postgres P') { |p| opts[:paths][:postgresql] = p }
        o.on('-h', '--help') { puts o; exit }
        o.on('--version') { puts "TripWire v#{TripWire::VERSION}"; exit }
      end.parse!(args)
      
      opts
    end
  end
end