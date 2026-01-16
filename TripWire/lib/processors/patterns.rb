module TripWire
  module Processors
    module Patterns
      # Common production incident patterns
      PATTERNS = {
        memory_leak: {
          keywords: ['out of memory', 'heap', 'gc', 'memory exhausted', 'cannot allocate'],
          severity: 'CRITICAL',
          description: 'Possible memory leak or insufficient memory'
        },
        database_connection: {
          keywords: ['connection pool', 'too many connections', 'deadlock', 'timeout', 'could not connect'],
          severity: 'CRITICAL',
          description: 'Database connectivity or performance issue'
        },
        disk_space: {
          keywords: ['disk full', 'no space left', 'disk quota', 'insufficient disk'],
          severity: 'CRITICAL',
          description: 'Disk space exhaustion'
        },
        network_timeout: {
          keywords: ['timeout', 'connection refused', 'network unreachable', 'host unreachable'],
          severity: 'HIGH',
          description: 'Network connectivity issues'
        },
        authentication: {
          keywords: ['authentication failed', 'unauthorized', 'access denied', 'invalid credentials'],
          severity: 'HIGH',
          description: 'Authentication or authorization failures'
        },
        service_unavailable: {
          keywords: ['service unavailable', 'http 503', 'cannot reach', 'endpoint not found'],
          severity: 'CRITICAL',
          description: 'Service availability issue'
        },
        high_cpu: {
          keywords: ['cpu usage', 'high cpu', 'cpu spike', 'processor'],
          severity: 'HIGH',
          description: 'High CPU utilization'
        },
        deadlock: {
          keywords: ['deadlock', 'lock timeout', 'waiting for lock'],
          severity: 'HIGH',
          description: 'Database or resource deadlock'
        },
        crash: {
          keywords: ['crash', 'segfault', 'core dump', 'fatal error', 'panic'],
          severity: 'CRITICAL',
          description: 'Application or system crash'
        }
      }
      
      def self.detect(root, output_dir)
        log = TripWire::Logger.instance
        log.info "Detecting incident patterns..."
        
        matches = Hash.new { |h, k| h[k] = [] }
        
        # Scan all events for patterns
        Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
          next if tsv.include?('/Reports/') || tsv.include?('/Alerts/')
          
          source = File.basename(File.dirname(tsv))
          
          TripWire::TSV.each(tsv) do |row|
            msg = (row['message'] || row['Message'] || '').to_s.downcase
            ts = parse_timestamp(row)
            
            PATTERNS.each do |pattern_name, pattern_def|
              if pattern_def[:keywords].any? { |kw| msg.include?(kw.downcase) }
                matches[pattern_name] << {
                  time: ts,
                  source: source,
                  message: (row['message'] || row['Message'])[0...200],
                  severity: row['severity'] || row['LevelDisplayName']
                }
              end
            end
          end
        end
        
        write_pattern_report(matches, output_dir)
        
        log.info "  ✓ Found #{matches.values.map(&:size).sum} pattern matches across #{matches.size} pattern types"
      end
      
      private
      
      def self.parse_timestamp(row)
        ts = row['timestamp'] || row['TimeCreated'] || row['Timestamp']
        return nil unless ts && !ts.strip.empty?
        Time.parse(ts) rescue nil
      end
      
      def self.write_pattern_report(matches, dir)
        File.open(File.join(dir, '00_PATTERN_ANALYSIS.txt'), 'w:UTF-8') do |f|
          f.puts "=" * 100
          f.puts "INCIDENT PATTERN DETECTION"
          f.puts "=" * 100
          f.puts
          
          if matches.empty?
            f.puts "No known incident patterns detected."
            f.puts
            f.puts "This could mean:"
            f.puts "  • The incident was caused by a novel issue"
            f.puts "  • The relevant logs are not being collected"
            f.puts "  • The time window doesn't capture the root cause"
            return
          end
          
          # Summary
          f.puts "DETECTED PATTERNS (#{matches.size} types):"
          f.puts "-" * 100
          matches.sort_by { |_, v| -v.size }.each do |pattern_name, occurrences|
            pattern_def = PATTERNS[pattern_name]
            f.puts "  #{pattern_name.to_s.upcase.ljust(25)} │ #{pattern_def[:severity].ljust(10)} │ #{occurrences.size} occurrence(s)"
            f.puts "    └─ #{pattern_def[:description]}"
          end
          f.puts
          
          # Detailed breakdown
          f.puts "DETAILED BREAKDOWN:"
          f.puts "=" * 100
          
          matches.sort_by { |_, v| -v.size }.each do |pattern_name, occurrences|
            pattern_def = PATTERNS[pattern_name]
            
            f.puts
            f.puts "┌─ #{pattern_name.to_s.upcase} (#{pattern_def[:severity]})"
            f.puts "│  #{pattern_def[:description]}"
            f.puts "│  Occurrences: #{occurrences.size}"
            f.puts "│"
            
            # Timeline of occurrences
            timeline = occurrences.group_by { |o| o[:time] ? o[:time].strftime('%H:%M') : 'unknown' }
            f.puts "│  Timeline:"
            timeline.sort.first(10).each do |time, events|
              f.puts "│    [#{time}] #{events.size} event(s)"
            end
            
            # Sources affected
            sources = occurrences.map { |o| o[:source] }.uniq
            f.puts "│"
            f.puts "│  Affected Sources: #{sources.join(', ')}"
            f.puts "│"
            
            # Sample messages
            f.puts "│  Sample Messages:"
            occurrences.first(5).each do |occurrence|
              time_str = occurrence[:time] ? occurrence[:time].strftime('%H:%M:%S') : 'unknown'
              f.puts "│    [#{time_str}] #{occurrence[:source]}: #{occurrence[:message][0...70]}"
            end
            
            f.puts "└" + "─" * 99
          end
          
          # Root cause suggestions
          f.puts
          f.puts "=" * 100
          f.puts "LIKELY ROOT CAUSES (based on patterns):"
          f.puts "-" * 100
          
          suggestions = generate_suggestions(matches)
          suggestions.each_with_index do |suggestion, idx|
            f.puts "  #{idx + 1}. #{suggestion}"
          end
          
          f.puts
          f.puts "=" * 100
        end
      end
      
      def self.generate_suggestions(matches)
        suggestions = []
        
        # Priority order based on criticality
        if matches[:disk_space]&.any?
          suggestions << "DISK SPACE: Check disk usage immediately. Clean up logs or increase disk capacity."
        end
        
        if matches[:memory_leak]&.any?
          suggestions << "MEMORY: Investigate memory leak. Check heap dumps, recent deployments, or traffic spikes."
        end
        
        if matches[:database_connection]&.any? && matches[:service_unavailable]&.any?
          suggestions << "DATABASE CASCADE: Database issues likely caused service failures. Check DB connection pool settings."
        elsif matches[:database_connection]&.any?
          suggestions << "DATABASE: Check database connection pool size, query performance, and DB server health."
        end
        
        if matches[:crash]&.any?
          suggestions << "APPLICATION CRASH: Review stack traces, recent code changes, and crash dumps."
        end
        
        if matches[:network_timeout]&.any? && matches[:service_unavailable]&.any?
          suggestions << "NETWORK/SERVICE: Network issues may have caused service unavailability. Check network logs and firewall."
        end
        
        if matches[:authentication]&.any?
          auth_sources = matches[:authentication].map { |o| o[:source] }.uniq
          suggestions << "AUTHENTICATION: #{auth_sources.size} source(s) had auth failures. Check credentials, certificate expiry, or IDP status."
        end
        
        if matches[:deadlock]&.any?
          suggestions << "DEADLOCK: Database deadlocks detected. Review transaction isolation levels and query patterns."
        end
        
        if matches[:high_cpu]&.any?
          suggestions << "CPU: High CPU usage detected. Check for infinite loops, inefficient queries, or traffic spikes."
        end
        
        # Correlation suggestions
        if matches.size >= 3
          suggestions << "CASCADING FAILURE: Multiple pattern types detected - likely cascading failure. Review timeline for trigger event."
        end
        
        suggestions << "Review the timeline to understand the sequence of events." if suggestions.empty?
        
        suggestions
      end
    end
  end
end