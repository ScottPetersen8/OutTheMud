

module TripWire
  module Processors
    # Report Generator - Create Analysis-Ready Reports
    #
    # This module takes raw TSV files and cleans/formats them for analysis.
    # It handles encoding issues, malformed data, and produces clean reports.
    #
    # WHY REPORTS?
    # - Raw log data is messy (encoding issues, malformed lines, etc)
    # - Need to standardize for analysis
    # - Want to track what was skipped and why
    #
    # WHAT IT DOES
    # 1. Reads raw TSV files (might have encoding/format issues)
    # 2. Cleans each line (fixes encoding, removes control characters)
    # 3. Outputs clean TSV suitable for Excel/analysis
    # 4. Tracks statistics (rows processed, rows skipped, reasons)
    #
    # KEY CONCEPTS
    # - Bad encoding: Some logs have non-UTF8 characters
    #   Solution: Encode with replacement characters
    # - Malformed CSV: Some lines don't have correct number of columns
    #   Solution: Use relaxed TSV parsing (see read_relaxed_tsv)
    # - Control characters: Logs might contain tabs, newlines in message fields
    #   Solution: Replace with spaces to keep TSV clean
    #
    module Reports
      # Generate cleaned reports from all TSV files
      #
      # This is the main entry point that:
      # 1. Finds all TSV files
      # 2. Creates cleaned versions
      # 3. Produces summary statistics
      #
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
                      quote_char: '"') do |row|
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
          [s[0...first], s[first + 1...second], s[second + 1...last], s[last + 1..-1]]
        else
          s.split("\t", expected)
        end
      end
    end
  end
end