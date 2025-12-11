module TripWire
  module Processors
    module Alerts

      def self.extract(root, start_time, end_time, out_dir)
        TripWire::Logger.instance.info "Alerts: scanning #{root}"

        keywords = TripWire::Config::KEYWORDS
        if keywords.nil? || keywords.empty?
          TripWire::Logger.instance.warn "No KEYWORDS loaded — cannot detect alerts."
          return
        end

        pattern = Regexp.union(keywords.map { |k| /\b#{Regexp.escape(k)}\b/i })

        tsv_files = Dir.glob(File.join(root, '**', '*.tsv'))
        if tsv_files.empty?
          TripWire::Logger.instance.warn "No TSV files found under #{root}"
          return
        end

        FileUtils.mkdir_p(out_dir) unless Dir.exist?(out_dir)

        tsv_files.each do |tsv|
          begin
            process_file(tsv, pattern, start_time, end_time, out_dir)
          rescue => e
            TripWire::Logger.instance.error "Alert processing failed for #{tsv}: #{e.message}"
          end
        end
      end


      def self.process_file(tsv, pattern, start_time, end_time, out_dir)
        alerts = [%w[timestamp severity message source]]
        new_alerts = 0

        TripWire::TSV.each(tsv) do |row|
          message = extract_message(row)
          next unless message.match?(pattern)

          ts = extract_timestamp(row)
          next unless ts.between?(start_time, end_time)

          alerts << [
            ts.strftime('%Y-%m-%d %H:%M:%S'),
            "ALERT",
            TripWire::Utils.clean(message, 2000),
            File.basename(tsv)
          ]

          new_alerts += 1
          TripWire::Stats.instance.increment(:alerts)
        end

        return if new_alerts == 0

        out_file = File.join(out_dir, File.basename(tsv))
        TripWire::TSV.write(out_file, alerts)

        TripWire::Logger.instance.info "  🚨 #{new_alerts} alerts → #{File.basename(out_file)}"
      end



      def self.extract_message(row)
        row['message'] || row['Message'] || row.values.join(' ')
      end

      def self.extract_timestamp(row)
        raw = row['TimeCreated'] || row['timestamp'] || row.values.first
        Time.parse(raw) rescue Time.now
      end

    end
  end
end


