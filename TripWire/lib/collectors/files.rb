module TripWire
  module Collectors
    module Files
      def self.collect(name, path, st, et, dir, opts)
        tsv = File.join(dir, "#{name}.tsv")
        TripWire::Logger.instance.info "#{name}..." unless opts[:skip_log]

        stop_spinner = TripWire::Utils.spinner(name)
              
        unless Dir.exist?(path)
          stop_spinner.call
          TripWire::Logger.instance.warn "  Not found: #{path}"
          TripWire::TSV.write(tsv, [%w[timestamp severity message source]])
          return
        end
        
        rows, files = [%w[timestamp severity message source]], 0
        
        Dir.glob(File.join(path, '**', '*')).sort.each do |f|
          next unless File.file?(f)
          mt = File.mtime(f) rescue next
          next if !opts[:all_files] && !mt.between?(st, et)
          
          files += 1
          process_file(f, st, et, mt, rows)
        end
        
        TripWire::TSV.write(tsv, rows)
        TripWire::Stats.instance.increment(:files, files)
        stop_spinner.call
        TripWire::Logger.instance.info "  ✓ #{files} files, #{rows.size - 1} lines"
      rescue => e
        TripWire::Logger.instance.error "#{name}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end
      
      private
      
      def self.process_file(file, st, et, mtime, rows)
        File.foreach(file, encoding: 'bom|utf-8') do |ln|
          ts = TripWire::Utils.parse_timestamp(ln) || mtime
          next unless ts.between?(st, et)
          
          sev = TripWire::Utils.severity(ln)
          rows << [ts.strftime('%Y-%m-%d %H:%M:%S'), sev, TripWire::Utils.clean(ln), File.basename(file)]
          
          TripWire::Stats.instance.increment(:lines)
          TripWire::Stats.instance.increment(:err) if sev == 'ERROR'
          TripWire::Stats.instance.increment(:warn) if sev == 'WARN'
        end
      rescue
        # Skip unreadable files
      end
    end
  end
end