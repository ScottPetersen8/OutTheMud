module TripWire
  module Processors
    module Timeline
      def self.generate(root, dir, st, et)
        log = TripWire::Logger.instance
        log.info "Generating incident timeline..."
        
        events = collect_all_events(root)
        return log.warn("No events for timeline") if events.empty?
        
        # Sort chronologically
        events.sort_by! { |e| e[:time] }
        
        # Detect anomalies
        anomalies = detect_anomalies(events, st, et)
        
        # Generate reports
        write_timeline(events, anomalies, dir, st, et)
        write_summary(events, anomalies, dir, st, et)
        write_heatmap(events, dir, st, et)
        
        log.info "  ✓ Timeline: #{events.size} events, #{anomalies.size} anomalies detected"
      end
      
      private
      
      def self.collect_all_events(root)
        events = []
        
        Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
          next if tsv.include?('/Reports/') || tsv.include?('/Alerts/')
          
          source = File.basename(File.dirname(tsv))
          
          TripWire::TSV.each(tsv) do |row|
            ts = parse_timestamp(row)
            next unless ts
            
            events << {
              time: ts,
              source: source,
              severity: extract_severity(row),
              message: extract_message(row),
              event_id: row['Id'] || row['EventID'],
              raw: row
            }
          end
        end
        
        events
      end
      
      def self.detect_anomalies(events, st, et)
        anomalies = []
        window_size = 60 # 1 minute windows
        
        # Group events by minute
        buckets = events.group_by { |e| (e[:time].to_i / window_size) * window_size }
        
        # Calculate baseline (median events per minute)
        counts = buckets.values.map(&:size)
        baseline = counts.sort[counts.size / 2] || 0
        threshold = baseline * 3 # 3x normal = anomaly
        
        buckets.each do |bucket_time, bucket_events|
          count = bucket_events.size
          
          # Detect spikes
          if count > threshold && count > 10
            anomalies << {
              type: :spike,
              time: Time.at(bucket_time),
              count: count,
              baseline: baseline,
              events: bucket_events.first(10) # Sample
            }
          end
          
          # Detect error clusters
          errors = bucket_events.select { |e| e[:severity] == 'ERROR' }
          if errors.size > 5
            anomalies << {
              type: :error_cluster,
              time: Time.at(bucket_time),
              count: errors.size,
              events: errors.first(10)
            }
          end
          
          # Detect cascading failures (errors across multiple sources)
          sources = bucket_events.select { |e| e[:severity] == 'ERROR' }
                                 .map { |e| e[:source] }
                                 .uniq
          if sources.size >= 3
            anomalies << {
              type: :cascading,
              time: Time.at(bucket_time),
              sources: sources,
              events: bucket_events.select { |e| e[:severity] == 'ERROR' }.first(15)
            }
          end
        end
        
        anomalies.sort_by { |a| a[:time] }
      end
      
      def self.write_timeline(events, anomalies, dir, st, et)
        File.open(File.join(dir, '00_TIMELINE.txt'), 'w:UTF-8') do |f|
          f.puts "=" * 120
          f.puts "INCIDENT TIMELINE".center(120)
          f.puts "Window: #{st.strftime('%Y-%m-%d %H:%M:%S')} → #{et.strftime('%Y-%m-%d %H:%M:%S')}".center(120)
          f.puts "=" * 120
          f.puts
          
          # Mark anomaly windows
          anomaly_times = anomalies.map { |a| a[:time] }.to_set
          
          current_minute = nil
          events.each do |evt|
            minute = Time.at((evt[:time].to_i / 60) * 60)
            
            # Insert anomaly marker
            if minute != current_minute && anomaly_times.include?(minute)
              f.puts
              f.puts "⚠" * 60
              anomaly = anomalies.find { |a| a[:time] == minute }
              f.puts "  ANOMALY DETECTED: #{anomaly[:type].to_s.upcase} at #{minute.strftime('%H:%M')}"
              f.puts "⚠" * 60
              f.puts
              current_minute = minute
            end
            
            severity_icon = case evt[:severity]
            when 'ERROR', 'FATAL', 'CRITICAL' then '❌'
            when 'WARN', 'WARNING' then '⚠️ '
            else '  '
            end
            
            f.puts "[#{evt[:time].strftime('%H:%M:%S')}] #{severity_icon} #{evt[:severity].ljust(8)} │ #{evt[:source].ljust(15)} │ #{evt[:message][0...80]}"
          end
          
          f.puts
          f.puts "=" * 120
          f.puts "Total Events: #{events.size}"
        end
      end
      
      def self.write_summary(events, anomalies, dir, st, et)
        File.open(File.join(dir, '00_INCIDENT_SUMMARY.txt'), 'w:UTF-8') do |f|
          f.puts "=" * 100
          f.puts "INCIDENT ANALYSIS SUMMARY"
          f.puts "=" * 100
          f.puts
          f.puts "Time Window: #{st.strftime('%Y-%m-%d %H:%M:%S')} → #{et.strftime('%Y-%m-%d %H:%M:%S')}"
          f.puts "Duration: #{((et - st) / 60).round(1)} minutes"
          f.puts
          
          # Event breakdown
          f.puts "EVENT BREAKDOWN:"
          f.puts "-" * 100
          by_severity = events.group_by { |e| e[:severity] }
          by_severity.each do |sev, evts|
            f.puts "  #{sev.ljust(10)}: #{evts.size.to_s.rjust(6)} events"
          end
          f.puts
          
          # Source breakdown
          f.puts "BY SOURCE:"
          f.puts "-" * 100
          by_source = events.group_by { |e| e[:source] }
          by_source.sort_by { |_, v| -v.size }.each do |src, evts|
            errors = evts.count { |e| e[:severity] == 'ERROR' }
            f.puts "  #{src.ljust(20)}: #{evts.size.to_s.rjust(6)} events (#{errors} errors)"
          end
          f.puts
          
          # Anomalies
          if anomalies.any?
            f.puts "ANOMALIES DETECTED:"
            f.puts "-" * 100
            anomalies.group_by { |a| a[:type] }.each do |type, anoms|
              f.puts "  #{type.to_s.upcase}: #{anoms.size} occurrence(s)"
              anoms.first(5).each do |anom|
                f.puts "    - #{anom[:time].strftime('%H:%M:%S')}: #{anom[:count] || anom[:sources]&.size} events"
              end
            end
            f.puts
          end
          
          # Timeline of critical moments
          f.puts "CRITICAL MOMENTS (Errors & Anomalies):"
          f.puts "-" * 100
          
          critical = events.select { |e| e[:severity] == 'ERROR' || e[:severity] == 'FATAL' }
          critical.first(20).each do |evt|
            f.puts "  [#{evt[:time].strftime('%H:%M:%S')}] #{evt[:source].ljust(15)} │ #{evt[:message][0...70]}"
          end
          
          f.puts
          f.puts "=" * 100
        end
      end
      
      def self.write_heatmap(events, dir, st, et)
        File.open(File.join(dir, '00_HEATMAP.txt'), 'w:UTF-8') do |f|
          f.puts "=" * 100
          f.puts "EVENT HEATMAP (Events per minute)"
          f.puts "=" * 100
          f.puts
          
          # Group by minute
          buckets = events.group_by { |e| Time.at((e[:time].to_i / 60) * 60) }
          
          # Calculate max for scaling
          max_count = buckets.values.map(&:size).max || 1
          
          buckets.sort.each do |time, bucket_events|
            count = bucket_events.size
            errors = bucket_events.count { |e| e[:severity] == 'ERROR' }
            
            # Create bar graph
            bar_length = (count.to_f / max_count * 50).round
            bar = '█' * bar_length
            
            error_indicator = errors > 0 ? " (#{errors} errors)" : ""
            
            f.puts "[#{time.strftime('%H:%M')}] #{count.to_s.rjust(5)} │ #{bar}#{error_indicator}"
          end
          
          f.puts
          f.puts "Scale: Each █ ≈ #{(max_count / 50.0).round(1)} events"
        end
      end
      
      # Helper methods
      def self.parse_timestamp(row)
        ts = row['timestamp'] || row['TimeCreated'] || row['Timestamp']
        return nil unless ts && !ts.strip.empty?
        Time.parse(ts) rescue nil
      end
      
      def self.extract_severity(row)
        (row['severity'] || row['LevelDisplayName'] || 'INFO').to_s.strip
      end
      
      def self.extract_message(row)
        msg = row['message'] || row['Message'] || row['log_line'] || ''
        msg.to_s.gsub(/[\r\n\t]+/, ' ').strip[0...500]
      end
    end
  end
end