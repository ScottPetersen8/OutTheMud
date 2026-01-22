# lib/analyzers/correlation.rb
# Smart log correlation and root cause analysis

module TripWire
  module Analyzers
    module Correlation
      
      FAILURE_PATTERNS = {
        database_connection_exhausted: {
          trigger: /FATAL.*too many connections|connection pool exhausted/i,
          source_type: 'PostgreSQL',
          look_ahead: 60,
          expected_effects: [
            {pattern: /connection.*refused|timeout.*database/i, delay: [0, 30]},
            {pattern: /cannot connect|database.*unavailable/i, delay: [0, 30]}
          ],
          severity: :critical,
          description: 'Database connection pool exhaustion'
        },
        database_crash: {
          trigger: /database system.*shutting down|panic|abnormal.*shutdown/i,
          source_type: 'PostgreSQL',
          look_ahead: 120,
          expected_effects: [
            {pattern: /connection.*refused|could not connect/i, delay: [0, 60]},
            {pattern: /database.*not.*available/i, delay: [0, 60]}
          ],
          severity: :critical,
          description: 'Database crash or shutdown'
        },
        out_of_memory: {
          trigger: /out of memory|cannot allocate|OOM/i,
          source_type: nil,
          look_ahead: 30,
          expected_effects: [
            {pattern: /killed|terminated|exit.*137/i, delay: [0, 15]},
            {pattern: /crash|fatal|core dump/i, delay: [0, 15]}
          ],
          severity: :critical,
          description: 'Out of memory condition'
        },
        disk_full: {
          trigger: /no space left|disk full|write failed.*space/i,
          source_type: nil,
          look_ahead: 60,
          expected_effects: [
            {pattern: /cannot write|write.*fail|IO error/i, delay: [0, 30]},
            {pattern: /crash|fatal/i, delay: [0, 30]}
          ],
          severity: :critical,
          description: 'Disk space exhausted'
        },
        agent_connection_loss: {
          trigger: /connection.*lost|disconnected from|connection.*closed unexpectedly/i,
          source_type: 'Datadog_Agent',
          look_ahead: 30,
          expected_effects: [
            {pattern: /reconnect|retry|attempting.*connect/i, delay: [0, 20]}
          ],
          severity: :warning,
          description: 'Monitoring agent connection lost'
        }
      }.freeze
      
      def self.analyze(root_dir, st, et, opts)
        log = TripWire::Logger.instance
        log.info "🔍 Analyzing logs for correlations and root causes..."
        
        timeline = build_timeline(root_dir, st, et)
        log.info "  Built timeline with #{timeline.size} events"
        
        incidents = detect_failure_patterns(timeline)
        log.info "  Detected #{incidents.size} potential incidents"
        
        correlations = find_correlations(timeline, incidents)
        log.info "  Found #{correlations.size} correlations"
        
        analysis_dir = File.join(root_dir, 'Analysis')
        FileUtils.mkdir_p(analysis_dir)
        
        generate_analysis_report(incidents, correlations, timeline, analysis_dir)
      end
      
      private
      
      def self.build_timeline(root_dir, st, et)
        timeline = []
        tsv_files = Dir.glob(File.join(root_dir, '**', '*.tsv'))
        
        tsv_files.each do |tsv_file|
          log_type = extract_log_type(tsv_file)
          
          TripWire::TSV.each(tsv_file) do |row|
            timestamp_str = row['timestamp'] || row['TimeCreated']
            next unless timestamp_str
            
            begin
              ts = Time.parse(timestamp_str)
              next unless ts.between?(st, et)
              
              timeline << {
                timestamp: ts,
                severity: row['severity'] || row['LevelDisplayName'] || 'INFO',
                message: row['message'] || row['Message'] || '',
                source: row['source'] || row['ProviderName'] || File.basename(tsv_file, '.tsv'),
                log_type: log_type,
                file_path: row['file_path'] || tsv_file
              }
            rescue
            end
          end
        end
        
        timeline.sort_by! { |event| event[:timestamp] }
        timeline
      end
      
      def self.extract_log_type(tsv_path)
        parts = tsv_path.split(/[\/\\]/)
        
        if idx = parts.index('Sniffer')
          parts[idx + 2] || 'Unknown'
        else
          File.basename(tsv_path, '.tsv')
        end
      end
      
      def self.detect_failure_patterns(timeline)
        incidents = []
        
        timeline.each_with_index do |event, idx|
          FAILURE_PATTERNS.each do |pattern_name, pattern_config|
            next unless event[:message] =~ pattern_config[:trigger]
            next if pattern_config[:source_type] && event[:log_type] != pattern_config[:source_type]
            
            effects = find_effects(timeline, idx, pattern_config, event[:timestamp])
            
            incidents << {
              pattern: pattern_name,
              root_event: event,
              effects: effects,
              severity: pattern_config[:severity],
              description: pattern_config[:description]
            }
          end
        end
        
        incidents
      end
      
      def self.find_effects(timeline, trigger_idx, pattern_config, trigger_time)
        effects = []
        look_ahead_seconds = pattern_config[:look_ahead]
        
        ((trigger_idx + 1)...timeline.size).each do |idx|
          event = timeline[idx]
          time_diff = event[:timestamp] - trigger_time
          
          break if time_diff > look_ahead_seconds
          
          pattern_config[:expected_effects].each do |effect_config|
            if event[:message] =~ effect_config[:pattern]
              min_delay, max_delay = effect_config[:delay]
              if time_diff >= min_delay && time_diff <= max_delay
                effects << {
                  event: event,
                  delay: time_diff,
                  pattern: effect_config[:pattern]
                }
              end
            end
          end
        end
        
        effects
      end
      
      def self.find_correlations(timeline, incidents)
        correlations = []
        window_size = 30
        time_buckets = {}
        
        timeline.each do |event|
          bucket = (event[:timestamp].to_i / window_size) * window_size
          time_buckets[bucket] ||= []
          time_buckets[bucket] << event
        end
        
        time_buckets.each do |bucket_time, events|
          errors = events.select { |e| e[:severity] == 'ERROR' || e[:message] =~ /error|fail|crash/i }
          next if errors.size < 2
          
          sources = errors.map { |e| e[:log_type] }.uniq
          if sources.size > 1
            correlations << {
              time_window: Time.at(bucket_time),
              events: errors,
              sources: sources,
              type: :temporal_correlation
            }
          end
        end
        
        correlations
      end
      
      def self.generate_analysis_report(incidents, correlations, timeline, output_dir)
        if incidents.empty? && correlations.empty?
          TripWire::Logger.instance.info "  No incidents or correlations - skipping analysis report"
          return
        end
        
        FileUtils.mkdir_p(output_dir)
        report_path = File.join(output_dir, 'INCIDENT_ANALYSIS.txt')
        
        content = <<-HEADER
═══════════════════════════════════════════════════════════════════
TripWire v4.0 - Incident Analysis Report
═══════════════════════════════════════════════════════════════════
Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}
Timeline: #{timeline.first[:timestamp].strftime('%Y-%m-%d %H:%M:%S')} → #{timeline.last[:timestamp].strftime('%Y-%m-%d %H:%M:%S')}
Total Events: #{timeline.size}
Incidents Detected: #{incidents.size}
Correlations Found: #{correlations.size}
═══════════════════════════════════════════════════════════════════

        HEADER
        
        if incidents.empty?
          content << "\n✅ NO CRITICAL INCIDENTS DETECTED\n"
          content << "All logs appear normal within the analyzed time period.\n"
        else
          content << "\n⚠️  INCIDENTS DETECTED\n\n"
          
          incidents.sort_by { |i| [i[:severity] == :critical ? 0 : 1, i[:root_event][:timestamp]] }.each_with_index do |incident, idx|
            content << format_incident(incident, idx + 1)
          end
        end
        
        if correlations.any?
          content << "\n\n📊 TEMPORAL CORRELATIONS\n\n"
          content << "Multiple services experienced issues simultaneously:\n\n"
          
          correlations.each do |corr|
            content << format_correlation(corr)
          end
        end
        
        content << "\n" << "═" * 70 << "\n"
        content << "END OF ANALYSIS\n"
        
        File.write(report_path, content)
        
        TripWire::Logger.instance.info "  Analysis Report: #{report_path}"
      end
      
      def self.format_incident(incident, number)
        root = incident[:root_event]
        severity_icon = incident[:severity] == :critical ? '🔴' : '⚠️ '
        
        output = <<-INCIDENT
#{severity_icon} INCIDENT ##{number}: #{incident[:description]}
─────────────────────────────────────────────────────────────────

ROOT CAUSE:
  Time:     #{root[:timestamp].strftime('%Y-%m-%d %H:%M:%S')}
  Source:   #{root[:log_type]} (#{root[:source]})
  Severity: #{root[:severity]}
  Message:  #{root[:message][0..200]}
  Location: #{root[:file_path]}

        INCIDENT
        
        if incident[:effects].any?
          output << "CASCADE EFFECTS (#{incident[:effects].size} events):\n"
          incident[:effects].each do |effect|
            e = effect[:event]
            output << sprintf("  [+%3ds] %s: %s\n",
                            effect[:delay].to_i,
                            e[:log_type],
                            e[:message][0..100])
          end
        else
          output << "NO CASCADE EFFECTS DETECTED\n"
        end
        
        output << "\n"
        output
      end
      
      def self.format_correlation(corr)
        output = "Time Window: #{corr[:time_window].strftime('%Y-%m-%d %H:%M:%S')} (+30s)\n"
        output << "Affected Services: #{corr[:sources].join(', ')}\n"
        output << "Events:\n"
        
        corr[:events].each do |event|
          output << sprintf("  [%s] %s: %s\n",
                          event[:timestamp].strftime('%H:%M:%S'),
                          event[:log_type],
                          event[:message][0..80])
        end
        
        output << "\n"
        output
      end
    end
  end
end