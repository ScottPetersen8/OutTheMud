module TripWire
  module Processors
    module Reports
      def self.generate(root, dir)
        TripWire::Logger.instance.info "Reports..."
        
        Dir.glob(File.join(root, '**', '*.tsv')).each do |tsv|
          create_report(tsv, root, dir)
        end
      end
      
      private
      
      def self.create_report(tsv, root, dir)
        rel = tsv.sub(root + '/', '').gsub(/[\/\\]/, '_').sub(/([^_]+)_\1\.tsv$/, '\1.tsv')
        rpt = File.join(dir, rel.sub('.tsv', '.txt'))
        
        File.open(rpt, 'w:UTF-8') do |f|
          write_header(f, rel, tsv)
          cnt, skip = write_events(f, tsv)
          write_footer(f, cnt, skip)
        end
      rescue => e
        TripWire::Logger.instance.error "Report #{tsv}: #{e.message}"
      end
      
      def self.write_header(file, rel, tsv)
        file.puts "=" * 80, "TripWire: #{rel}", "=" * 80, ""
      end
      
      def self.write_events(file, tsv)
        cnt, skip = 0, 0
        
        TripWire::TSV.each(tsv) do |r|
          next (skip += 1) if r.values.all? { |v| v.nil? || v.strip.empty? }
          
          ts = extract_timestamp(r)
          lvl = extract_level(r)
          msg = TripWire::Utils.clean(r['Message'] || r['message'] || r.values.join(' | '))
          next (skip += 1) if msg.empty?
          
          src = extract_source(r, tsv)
          eid = extract_event_id(r)
          
          file.puts "[#{ts}] #{lvl.ljust(8)} | #{src[0...40].ljust(40)} | #{msg}#{eid.empty? ? '' : " [#{eid}]"}"
          cnt += 1
        end
        
        [cnt, skip]
      end
      
      def self.write_footer(file, cnt, skip)
        file.puts "", "=" * 80, "Total: #{cnt} events"
        file.puts "Skipped: #{skip}" if skip > 0
      end
      
      def self.extract_timestamp(row)
        ts = row['TimeCreated'] || row['timestamp']
        ts && !ts.strip.empty? ? (Time.parse(ts).strftime('%Y-%m-%d %H:%M:%S') rescue ts[0...19]) : Time.now.strftime('%Y-%m-%d %H:%M:%S')
      end
      
      def self.extract_level(row)
        (row['LevelDisplayName'] || row['severity'] || 'INFO').strip
      end
      
      def self.extract_source(row, tsv)
        (row['ProviderName'] || row['source'] || File.basename(tsv)).strip
      end
      
      def self.extract_event_id(row)
        (row['Id'] || row['EventID'] || '').strip
      end
    end
  end
end
