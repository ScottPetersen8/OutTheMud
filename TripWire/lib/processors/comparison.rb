module TripWire
  module Processors
    module Comparison
      def self.analyze(baseline_dir, incident_dir, output_dir)
        log = TripWire::Logger.instance
        log.info "Comparing baseline vs incident..."
        
        baseline_stats = collect_stats(baseline_dir)
        incident_stats = collect_stats(incident_dir)
        
        differences = calculate_differences(baseline_stats, incident_stats)
        
        write_comparison_report(baseline_stats, incident_stats, differences, output_dir)
        
        log.info "  ✓ Comparison complete"
      end
      
      private
      
      def self.collect_stats(dir)
        stats = {
          total_events: 0,
          by_severity: Hash.new(0),
          by_source: Hash.new(0),
          error_rate: 0.0,
          unique_errors: Set.new,
          event_patterns: Hash.new(0)
        }
        
        Dir.glob(File.join(dir, '**', '*.tsv')).each do |tsv|
          next if tsv.include?('/Reports/') || tsv.include?('/Alerts/')
          
          source = File.basename(File.dirname(tsv))
          
          TripWire::TSV.each(tsv) do |row|
            stats[:total_events] += 1
            
            severity = (row['severity'] || row['LevelDisplayName'] || 'INFO').to_s.strip
            stats[:by_severity][severity] += 1
            stats[:by_source][source] += 1
            
            if severity == 'ERROR' || severity == 'FATAL'
              msg = row['message'] || row['Message'] || ''
              # Extract error pattern (first 50 chars)
              pattern = msg.to_s[0...50].gsub(/\d+/, 'N')
              stats[:unique_errors].add(pattern)
              stats[:event_patterns][pattern] += 1
            end
          end
        end
        
        stats[:error_rate] = stats[:total_events] > 0 ? 
          (stats[:by_severity]['ERROR'].to_f / stats[:total_events] * 100) : 0.0
        
        stats
      end
      
      def self.calculate_differences(baseline, incident)
        {
          event_increase: incident[:total_events] - baseline[:total_events],
          event_increase_pct: calculate_pct_change(baseline[:total_events], incident[:total_events]),
          error_increase: incident[:by_severity]['ERROR'] - baseline[:by_severity]['ERROR'],
          error_rate_change: incident[:error_rate] - baseline[:error_rate],
          new_error_patterns: incident[:unique_errors] - baseline[:unique_errors],
          source_changes: calculate_source_changes(baseline[:by_source], incident[:by_source])
        }
      end
      
      def self.calculate_pct_change(old_val, new_val)
        return 0.0 if old_val == 0
        ((new_val - old_val).to_f / old_val * 100).round(1)
      end
      
      def self.calculate_source_changes(baseline_sources, incident_sources)
        changes = {}
        
        all_sources = (baseline_sources.keys + incident_sources.keys).uniq
        
        all_sources.each do |source|
          base = baseline_sources[source] || 0
          inc = incident_sources[source] || 0
          pct = calculate_pct_change(base, inc)
          
          changes[source] = {
            baseline: base,
            incident: inc,
            change: inc - base,
            change_pct: pct
          } if pct.abs > 10 # Only report significant changes
        end
        
        changes
      end
      
      def self.write_comparison_report(baseline, incident, diff, dir)
        File.open(File.join(dir, '00_BASELINE_COMPARISON.txt'), 'w:UTF-8') do |f|
          f.puts "=" * 100
          f.puts "BASELINE vs INCIDENT COMPARISON"
          f.puts "=" * 100
          f.puts
          
          # Overall metrics
          f.puts "OVERALL METRICS:"
          f.puts "-" * 100
          f.puts "  Total Events:"
          f.puts "    Baseline:  #{baseline[:total_events]}"
          f.puts "    Incident:  #{incident[:total_events]}"
          f.puts "    Change:    #{format_change(diff[:event_increase], diff[:event_increase_pct])}"
          f.puts
          
          f.puts "  Error Events:"
          f.puts "    Baseline:  #{baseline[:by_severity]['ERROR']}"
          f.puts "    Incident:  #{incident[:by_severity]['ERROR']}"
          f.puts "    Change:    #{format_change(diff[:error_increase], diff[:error_rate_change])}"
          f.puts
          
          # Severity breakdown
          f.puts "SEVERITY COMPARISON:"
          f.puts "-" * 100
          f.printf("  %-15s %15s %15s %20s\n", "Severity", "Baseline", "Incident", "Change")
          f.puts "  " + "-" * 65
          
          all_severities = (baseline[:by_severity].keys + incident[:by_severity].keys).uniq.sort
          all_severities.each do |sev|
            base = baseline[:by_severity][sev] || 0
            inc = incident[:by_severity][sev] || 0
            change = inc - base
            pct = calculate_pct_change(base, inc)
            
            f.printf("  %-15s %15d %15d %10d (%+.1f%%)\n", sev, base, inc, change, pct)
          end
          f.puts
          
          # Source changes
          if diff[:source_changes].any?
            f.puts "SIGNIFICANT SOURCE CHANGES:"
            f.puts "-" * 100
            f.printf("  %-20s %12s %12s %15s\n", "Source", "Baseline", "Incident", "Change")
            f.puts "  " + "-" * 60
            
            diff[:source_changes].sort_by { |_, v| -v[:change].abs }.each do |source, data|
              f.printf("  %-20s %12d %12d %8d (%+.1f%%)\n", 
                       source, data[:baseline], data[:incident], 
                       data[:change], data[:change_pct])
            end
            f.puts
          end
          
          # New error patterns
          if diff[:new_error_patterns].any?
            f.puts "NEW ERROR PATTERNS (not seen in baseline):"
            f.puts "-" * 100
            diff[:new_error_patterns].first(20).each do |pattern|
              count = incident[:event_patterns][pattern]
              f.puts "  [#{count}x] #{pattern}"
            end
            f.puts
          end
          
          # Key findings
          f.puts "KEY FINDINGS:"
          f.puts "-" * 100
          findings = generate_findings(baseline, incident, diff)
          findings.each { |finding| f.puts "  • #{finding}" }
          
          f.puts
          f.puts "=" * 100
        end
      end
      
      def self.format_change(absolute, percentage)
        sign = absolute >= 0 ? '+' : ''
        "#{sign}#{absolute} (#{sign}#{percentage}%)"
      end
      
      def self.generate_findings(baseline, incident, diff)
        findings = []
        
        if diff[:event_increase_pct] > 50
          findings << "Event volume increased significantly (#{diff[:event_increase_pct]}%)"
        end
        
        if diff[:error_increase] > 100
          findings << "Error count spiked dramatically (+#{diff[:error_increase]} errors)"
        end
        
        if diff[:error_rate_change] > 5
          findings << "Error rate increased from #{baseline[:error_rate].round(1)}% to #{incident[:error_rate].round(1)}%"
        end
        
        if diff[:new_error_patterns].size > 0
          findings << "#{diff[:new_error_patterns].size} new error pattern(s) detected"
        end
        
        # Find biggest source change
        if diff[:source_changes].any?
          biggest = diff[:source_changes].max_by { |_, v| v[:change].abs }
          if biggest
            src, data = biggest
            findings << "#{src} had largest change: #{format_change(data[:change], data[:change_pct])}"
          end
        end
        
        findings << "No significant anomalies detected" if findings.empty?
        
        findings
      end
    end
  end
end