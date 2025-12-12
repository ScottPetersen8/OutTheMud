module TripWire
  module Collectors
    module Windows
      def self.collect(logs, st, et, dir, opts)
        if opts[:parallel]
          logs.map { |l| Thread.new { collect_single(l, st, et, dir, opts) } }.each(&:join)
        else
          logs.each { |l| collect_single(l, st, et, dir, opts) }
        end
      end
      
      def self.collect_single(log, st, et, dir, opts)
        tsv = File.join(dir, log, "#{log}.tsv")
        FileUtils.mkdir_p(File.dirname(tsv))
        
        TripWire::Logger.instance.info "Windows #{log}..."
        
        filters = build_filters(log, opts)
        ps_script = build_script(log, st, et, tsv, filters)
        
        stop = TripWire::Utils.spinner("#{log}")
        TripWire::PowerShell.run(ps_script)
        stop.call
        
        TripWire::TSV.write(tsv, [%w[TimeCreated Id LevelDisplayName ProviderName Message]]) unless File.exist?(tsv)
        
        count_and_log(tsv, log)
      rescue => e
        TripWire::Logger.instance.error "#{log}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end
      
      private
      
      def self.build_filters(log, opts)
        filters = ["LogName='#{log}'", "StartTime=$start", "EndTime=$end"]
        filters << "ID=#{TripWire::Config::SECURITY_IDS.join(',')}" if log == 'Security' && !opts[:all_sec]
        filters << "Level=1,2,3" if log != 'Security' && !opts[:all_lvl]
        filters
      end
      
      def self.build_script(log, st, et, tsv, filters)
        <<~PS
          $start = [datetime]'#{st.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
          $end = [datetime]'#{et.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}'
          try {
            $e = Get-WinEvent -FilterHashtable @{#{filters.join('; ')}} -MaxEvents 10000 -EA Stop |
              Select TimeCreated,Id,LevelDisplayName,ProviderName,Message
            if ($e) { $e | ConvertTo-Csv -Delimiter "`t" -NoType | Out-File '#{tsv}' -Encoding utf8 -Force }
            else { "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force }
          } catch { "TimeCreated`tId`tLevelDisplayName`tProviderName`tMessage" | Out-File '#{tsv}' -Encoding utf8 -Force }
        PS
      end
      
      def self.count_and_log(tsv, log)
        cnt = File.exist?(tsv) ? [File.readlines(tsv).count - 1, 0].max : 0
        TripWire::Stats.instance.increment(:lines, cnt)
        TripWire::Stats.instance.increment(:files)
        TripWire::Logger.instance.info "  ✓ #{cnt} events"
      end
    end
  end
end