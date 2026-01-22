# lib/collectors/signature_learner.rb - TRIMMED VERSION
# Dynamic log signature learning - learn patterns from actual logs on the machine

require 'find'

module TripWire
  module Collectors
    module SignatureLearner
      class LearnedSignature
        attr_reader :log_type, :example_file, :patterns, :characteristics, :confidence
        attr_writer :patterns, :characteristics
        
        def initialize(log_type, example_file)
          @log_type = log_type
          @example_file = example_file
          @patterns = []
          @characteristics = {}
          @confidence = 0.0
        end
      end
      
      def self.learn_from_machine(search_paths = nil, max_examples = 5)
        log = TripWire::Logger.instance
        examples = find_example_logs(search_paths)
        return {} if examples.empty?
        
        log.info "📚 Found #{examples.size} potential example logs"
        learned = {}
        
        examples.each do |file_path|
          sig = learn_from_file(file_path)
          next unless sig && sig.confidence > 0.5
          learned[sig.log_type] = sig
          log.info "  ✓ Learned: #{sig.log_type} (confidence: #{(sig.confidence * 100).round}%)"
          break if learned.size >= max_examples
        end
        learned
      end
      
      def self.find_example_logs(search_paths = nil)
        paths_to_search = search_paths || default_search_paths
        examples = []
        
        paths_to_search.each do |path|
          next unless File.exist?(path)
          Find.find(path) do |file|
            next unless File.file?(file) && file =~ /\.(log|txt|out)$/i && File.size(file) >= 100
            examples << file
            break
          end
          break if examples.size >= 5
        end
        examples
      rescue
        []
      end
      
      def self.learn_from_file(file_path)
        lines = read_sample_lines(file_path, 100)
        return nil if lines.empty?
        
        sig = LearnedSignature.new(infer_log_type(file_path), file_path)
        sig.characteristics = analyze_structure(lines)
        sig.patterns = extract_patterns(lines, sig.characteristics)
        sig.instance_variable_set(:@confidence, calculate_confidence(sig))
        sig
      rescue
        nil
      end
      
      def self.read_sample_lines(file_path, max_lines = 100)
        lines = []
        File.open(file_path, 'r:bom|utf-8', invalid: :replace) do |f|
          max_lines.times { line = f.gets; break unless line; lines << line.strip }
        end
        lines.reject(&:empty?)
      rescue
        []
      end
      
      def self.infer_log_type(file_path)
        path_lower = file_path.downcase
        case path_lower
        when /datadog|dd-agent/ then 'Datadog_Agent'
        when /postgresql|postgres/ then 'PostgreSQL'
        when /mysql|mariadb/ then 'MySQL'
        when /mongodb|mongo/ then 'MongoDB'
        when /nginx/ then 'Nginx'
        when /apache|httpd/ then 'Apache'
        when /iis|inetpub/ then 'IIS'
        when /docker/ then 'Docker'
        when /elasticsearch/ then 'Elasticsearch'
        when /syslog|messages|auth\.log/ then 'Syslog'
        else "#{File.basename(File.dirname(file_path)).capitalize}_Log"
        end
      end
      
      def self.analyze_structure(lines)
        total_len = lines.inject(0) { |s, l| s + l.length }
        {
          total_lines: lines.size,
          avg_line_length: total_len / [lines.size, 1].max,
          has_timestamps: lines.any? { |l| l =~ /\d{4}-\d{2}-\d{2}|^\w{3}\s+\d{1,2}/ },
          log_levels: detect_log_levels(lines),
          json_structured: lines.count { |l| l.start_with?('{') || l.start_with?('[') } > (lines.size / 2)
        }
      end
      
      def self.extract_patterns(lines, characteristics)
        patterns = []
        lines.each do |line|
          next if line.length > 500
          patterns << /error|failed|exception|fatal|critical/i if line =~ /error|failed|exception|fatal|critical/i
          patterns << /warning|warn|deprecated/i if line =~ /warning|warn|deprecated/i
          patterns << /info|information|status/i if line =~ /info|information|status/i
          patterns << /debug|trace|verbose/i if line =~ /debug|trace|verbose/i
        end
        
        patterns.uniq!
        if characteristics[:has_timestamps]
          patterns << /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/
          patterns << /\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/
        end
        patterns
      end
      
      def self.detect_log_levels(lines)
        levels = {}
        {
          'ERROR' => /\bERROR\b|\bFATAL\b|\bCRITICAL\b/i,
          'WARNING' => /\bWARN/i,
          'INFO' => /\bINFO\b/i,
          'DEBUG' => /\bDEBUG\b|\bTRACE\b/i
        }.each { |level, pattern| levels[level] = lines.count { |l| l =~ pattern } if lines.any? { |l| l =~ pattern } }
        levels
      end
      
      def self.calculate_confidence(signature)
        conf = 0.0
        conf += 0.2 if signature.patterns.size >= 3
        conf += 0.1 if signature.patterns.size >= 5
        conf += 0.2 if signature.characteristics[:has_timestamps]
        conf += 0.2 if signature.characteristics[:json_structured]
        conf += 0.1 if signature.characteristics[:log_levels].size > 0
        [conf, 0.95].min
      end
      
      def self.find_similar_logs(signature, search_paths)
        similar = []
        search_paths.each do |path|
          next unless File.exist?(path)
          Find.find(path) do |file|
            next unless File.file?(file) && file =~ /\.(log|txt|out)$/i && File.size(file) >= 100 && file != signature.example_file
            similar << file if matches_signature?(file, signature)
          end
        end
        similar
      rescue
        []
      end
      
      def self.matches_signature?(file_path, signature)
        lines = read_sample_lines(file_path, 50)
        return false if lines.empty?
        sample = lines.join("\n")
        matched = signature.patterns.count { |p| sample =~ p }
        (matched.to_f / [signature.patterns.size, 1].max) >= 0.5
      rescue
        false
      end
      
      def self.report_signatures(signatures)
        puts "\n" + "="*70
        puts "📚 LEARNED LOG SIGNATURES FROM THIS MACHINE"
        puts "="*70
        signatures.each do |_, sig|
          puts "\n🔍 #{sig.log_type}"
          puts "   Example: #{sig.example_file}"
          puts "   Confidence: #{(sig.confidence * 100).round}%"
          puts "   Patterns Found: #{sig.patterns.size}"
          puts "   Log Levels: #{sig.characteristics[:log_levels].keys.join(', ')}"
          puts "   Has Timestamps: #{sig.characteristics[:has_timestamps]}"
          puts "   JSON Structured: #{sig.characteristics[:json_structured]}"
        end
        puts "\n" + "="*70
      end
      
      private
      
      def self.default_search_paths
        paths = []
        if Gem.win_platform?
          ('C'..'Z').each do |letter|
            drive = "#{letter}:/"
            next unless Dir.exist?(drive)
            paths += ["#{letter}:/ProgramData", "#{letter}:/Program Files", "#{letter}:/Program Files (x86)", "#{letter}:/Windows/Logs"]
          end
          if ENV['USERPROFILE']
            user = ENV['USERPROFILE'].gsub('\\', '/')
            paths += ["#{user}/AppData/Local", "#{user}/AppData/Roaming", "#{user}/Documents"]
          end
        else
          paths = ['/var/log', '/var/lib', '/opt', '/usr/local/var/log', '/srv', '/home', '/tmp']
          paths << ENV['HOME'] if ENV['HOME']
        end
        paths.compact.uniq.select { |p| File.exist?(p) }
      end
    end
  end
end
