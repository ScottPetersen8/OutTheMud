

module TripWire
  module Processors
    module Reports
      def self.generate(root, dir)
        log = TripWire::Logger.instance
        log.info "Generating reports..."

        tsvs = Dir.glob(File.join(root, '**', '*.tsv'))
        return log.warn("No TSV files found under: #{root}") if tsvs.empty?

        FileUtils.mkdir_p(dir)

        total_events  = 0
        total_skipped = 0
        total_reports = 0

        tsvs.each do |tsv|
          begin
            cnt, skip, clean = create_report(tsv, root, dir)
            total_events  += cnt
            total_skipped += skip
            total_reports += 1
            log.info(cnt > 0 ? "   #{cnt} events → #{clean}" : "  #{File.basename(tsv)} produced an empty report")
            log.info("    skipped=#{skip}") if skip > 0
          rescue => e
            log.error "Failed #{File.basename(tsv)}: #{e.message}"
          end
        end

        log.info "  ✓ #{total_reports} report(s) written"
        log.info "  ✓ Total events: #{total_events}"
        log.info "  ✓ Total skipped: #{total_skipped}"
      end

      private

            def self.generate_timeline(root, dir)
        log = TripWire::Logger.instance
        log.info "Generating unified timeline..."
        
        timeline = []
        
        # Collect all events from all TSVs
        Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
          next if tsv.include?('/Reports/') || tsv.include?('/Alerts/')
          
          TripWire::TSV.each(tsv) do |row|
            ts = extract_timestamp(row)
            next unless ts
            
            timeline << {
              time: ts,
              source: File.basename(File.dirname(tsv)),
              severity: extract_level(row),
              message: (row['message'] || row['Message'] || '')[0...200]
            }
          end
        end
        
        # Sort chronologically
        timeline.sort_by! { |e| e[:time] }
        
        # Write unified timeline
        File.open(File.join(dir, 'TIMELINE.txt'), 'w') do |f|
          f.puts "=" * 100
          f.puts "UNIFIED INCIDENT TIMELINE"
          f.puts "=" * 100
          f.puts
          
          timeline.each do |evt|
            f.puts "[#{evt[:time].strftime('%H:%M:%S')}] #{evt[:severity].ljust(8)} #{evt[:source].ljust(15)} | #{evt[:message]}"
          end
        end
        
        log.info "  ✓ Timeline: #{timeline.size} events"
      end

      def self.create_report(tsv, root, dir)
        parts     = tsv.sub(root, '').split(/[\/\\]/).reject(&:empty?)
        base      = parts.last.sub('.tsv', '')
        category  = parts[-2] || "Report"

        # Normalization + tokenization helpers
        norm     = ->(s) { s.to_s.downcase.gsub(/[^\p{Alnum}]+/, '_').gsub(/_{2,}/, '_').sub(/^_+|_+$/, '') }
        tokenize = ->(s) { norm.call(s).split('_') }
        sanitize = ->(s) { s.to_s.gsub(/[^\p{Alnum}\._-]+/, '_').gsub(/_{2,}/, '_').sub(/^_+|_+$/, '') }

        cb = tokenize.call(category) # category tokens
        bb = tokenize.call(base)     # base tokens

        name_tokens =
          if bb[0, cb.length] == cb
            bb                  # Base already starts with category → base only
          elsif cb[0, bb.length] == bb
            cb                  # Category already starts with base → category only
          else
            combined = cb + bb  # Combine and drop adjacent duplicates
            dedup = [combined.first]
            combined.each_cons(2) { |a, b| dedup << b unless a == b }
            dedup
          end

        clean = sanitize.call("#{name_tokens.join('_')}.txt")

        rpt = File.join(dir, clean)
        FileUtils.mkdir_p(File.dirname(rpt))

        cnt  = 0
        skip = 0

        File.open(rpt, 'w:UTF-8') do |f|
          write_header(f, clean)
          cnt, skip = write_events(f, tsv)
          write_footer(f, cnt, skip)
        end

        [cnt, skip, clean]
      end

      def self.write_header(file, name)
        file.puts "=" * 80, "TripWire Report: #{name}", "=" * 80, ""
      end

      def self.write_events(file, tsv)
        require 'csv'
        cnt = skip = processed = 0

        begin
          CSV.foreach(tsv,
                      col_sep: "\t",
                      headers: true,
                      encoding: 'bom|utf-8',
                      quote_char: '"',
                      liberal_parsing: true) do |row|
            processed += 1
            cnt, skip = emit_row(file, row.to_hash, tsv, cnt, skip)
          end
        rescue CSV::MalformedCSVError
          read_relaxed_tsv(tsv).each do |row_hash|
            processed += 1
            cnt, skip = emit_row(file, row_hash, tsv, cnt, skip)
          end
        end

        [cnt, skip]
      end

      def self.emit_row(file, row, tsv, cnt, skip)
        msg = TripWire::Utils.clean(row['message'] || row['Message'] || '', 2000).to_s
        msg = msg.gsub(/[\r\n\t]+/, ' ').strip
        msg = msg.empty? ? "<no message>" : msg

        ts  = extract_timestamp(row)
        lvl = extract_level(row)
        src = extract_source(row, tsv)
        eid = extract_event_id(row)

        file.puts "[#{ts}] #{lvl.ljust(8)} | #{src[0...40].ljust(40)} | #{msg}#{eid.empty? ? '' : " [#{eid}]"}"
        [cnt + 1, skip]
      end

      def self.write_footer(file, cnt, skip)
        file.puts "", "=" * 80, "Total: #{cnt} events"
        file.puts "Skipped: #{skip}" if skip > 0
      end

      # --- Extractors ---
      def self.extract_timestamp(row)
        require 'time'
        ts = row['timestamp'] || row['TimeCreated'] || row['Timestamp']
        return Time.now.strftime('%Y-%m-%d %H:%M:%S') unless ts && !ts.strip.empty?
        Time.parse(ts).strftime('%Y-%m-%d %H:%M:%S') rescue ts.to_s[0...19]
      end

      def self.extract_level(row)
        (row['severity'] || row['LevelDisplayName'] || 'INFO').to_s.strip
      end

      def self.extract_source(row, tsv)
        (row['source'] || row['ProviderName'] || File.basename(tsv)).to_s.strip
      end

      def self.extract_event_id(row)
        (row['Id'] || row['EventID'] || '').to_s.strip
      end

      # --- Relaxed TSV reader ---
      def self.read_relaxed_tsv(tsv)
        Enumerator.new do |y|
          File.open(tsv, 'r:bom|utf-8') do |fh|
            headers = fh.gets&.strip&.split("\t")
            raise "Missing header row in #{tsv}" unless headers
            expected = headers.size

            buffer = +""
            fh.each_line do |line|
              buffer << line.delete("\r")
              next if buffer.count("\t") < expected - 1
              parts = split_record_relaxed(buffer.sub(/\n+\z/, ''), expected, headers)
              y << headers.zip(parts).to_h
              buffer.clear
            end

            unless buffer.empty?
              parts = split_record_relaxed(buffer.sub(/\n+\z/, ''), expected, headers)
              y << headers.zip(parts).to_h
            end
          end
        end
      end

      def self.split_record_relaxed(s, expected, headers)
        if headers == %w[timestamp severity message source]
          first  = s.index("\t")
          second = first && s.index("\t", first + 1)
          last   = s.rindex("\t")
          return s.split("\t", expected) unless first && second && last && last != second
          [s[0...first], s[first + 1...second], s[second + 1...last], s[last + 1..]]
        else
          s.split("\t", expected)
        end
      end
    end
  end
end