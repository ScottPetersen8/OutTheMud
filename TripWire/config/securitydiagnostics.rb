module TripWire
  module Collectors
    module Windows
      require 'time'

      def self.collect(logs, st, et, dir, opts = {})
        if opts[:parallel]
          threads = logs.map { |l| Thread.new { collect_single(l, st, et, dir, opts) } }
          threads.each(&:join)
        else
          logs.each { |l| collect_single(l, st, et, dir, opts) }
        end
      end

      def self.collect_single(log, st, et, dir, opts = {})
        safe_log = File.basename(log.to_s)
        tsv = File.join(dir, safe_log, "#{safe_log}.tsv")
        FileUtils.mkdir_p(File.dirname(tsv))

        TripWire::Logger.instance.info "Windows #{safe_log}..."

        filters = build_filters(safe_log, opts)
        max_events = opts.key?(:max_events) ? opts[:max_events].to_i : nil
        ps_script = build_script(safe_log, st, et, tsv, filters, max_events)

        # Disable spinner to avoid stream conflicts
        # stop = TripWire::Utils.spinner(safe_log)
        begin
          TripWire::PowerShell.run(ps_script)
        rescue => e
          TripWire::Logger.instance.error "PowerShell execution failed for #{safe_log}: #{e.message}"
        end

        # Ensure file has a TSV header if PowerShell didn't create it
        TripWire::TSV.write(tsv, [%w[TimeCreated Id LevelDisplayName ProviderName Message]]) unless File.exist?(tsv)

        count_and_log(tsv, safe_log, st, et)
      rescue => e
        TripWire::Logger.instance.error "#{log}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end

      private

      # By default collect all Security events. If caller wants the limited SECURITY_IDS set
      # they must pass opts[:only_sec_ids] = true.
      def self.build_filters(log, opts = {})
        filters = ["LogName='#{log}'", "StartTime=$start", "EndTime=$end"]

        if log == 'Security' && opts[:only_sec_ids]
          filters << "ID=#{TripWire::Config::SECURITY_IDS.join(',')}"
        end

        filters << "Level=1,2,3" if log != 'Security' && !opts[:all_lvl]
        filters
      end

      # Build the PowerShell script. Only include -MaxEvents if a value was provided.
      # FIXED: Use local time instead of UTC - Windows Event Logs use local time
      def self.build_script(log, st, et, tsv, filters, max_events)
        max_flag = max_events ? "-MaxEvents #{max_events}" : ""
        <<~PS
          $start = [datetime]'#{st.strftime('%Y-%m-%dT%H:%M:%S')}'
          $end = [datetime]'#{et.strftime('%Y-%m-%dT%H:%M:%S')}'
          try {
            $e = Get-WinEvent -FilterHashtable @{#{filters.join('; ')}} #{max_flag} -EA Stop |
              Select TimeCreated,Id,LevelDisplayName,ProviderName,Message
            if ($e) { $e | ConvertTo-Csv -Delimiter "`t" -NoType | Out-File '#{tsv}' -Encoding utf8 -Force }
            else { "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force }
          } catch { "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force }
        PS
      end

      def self.count_and_log(tsv, log, requested_start, requested_end)
        cnt = 0
        oldest_event = nil

        if File.exist?(tsv)
          File.open(tsv, 'r:bom|utf-8') do |f|
            # skip header if present
            begin
              f.readline
            rescue EOFError
              # empty file, nothing to count
            end

            f.each_line do |line|
              next if line.nil? || line.strip.empty?
              fields = line.strip.split("\t", -1)
              next if fields.empty? || fields[0].nil? || fields[0].strip.empty?
              cnt += 1
              begin
                ts = Time.parse(fields[0])
                oldest_event = ts if oldest_event.nil? || ts < oldest_event
              rescue
                # ignore parse errors for timestamp but keep counting the row
              end
            end
          end
        end

        TripWire::Stats.instance.increment(:lines, cnt)
        TripWire::Stats.instance.increment(:files)

        if cnt > 0 && oldest_event
          if oldest_event > requested_start
            gap_days = ((oldest_event - requested_start) / 86400.0).round(1)
            actual_days = ((requested_end - oldest_event) / 86400.0).round(1)
            requested_days = ((requested_end - requested_start) / 86400.0).round(1)
            TripWire::Logger.instance.warn "  ⚠  #{log}: Only #{actual_days} days available (requested #{requested_days} days) - #{gap_days} day gap"
            TripWire::Logger.summary.warn "#{log}: Data gap - requested from #{requested_start.strftime('%Y-%m-%d')}, oldest available #{oldest_event.strftime('%Y-%m-%d')}"
          end
        end

        TripWire::Logger.instance.info "  ✓ #{cnt} events"
      end
    end
  end
end