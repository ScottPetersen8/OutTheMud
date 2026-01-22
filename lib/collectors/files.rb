module TripWire
  module Collectors
    module Files
      def self.collect(name, path, st, et, dir, opts)
        log = TripWire::Logger.instance
        tsv = File.join(dir, "#{name}.tsv")
        log.info "#{name}..." unless opts[:skip_log]
        stop_spinner = TripWire::Utils.spinner(name) unless opts[:quiet]
        
        # Handle single file path (from sniffer)
        if File.file?(path)
          rows = [%w[timestamp severity message source]]
          begin
            mt = File.mtime(path)
            process_file(path, st, et, mt, rows, opts[:sniffer_mode])
          rescue => e
            # File error, continue
          end
          TripWire::TSV.write(tsv, rows)
          TripWire::Stats.instance.increment(:files, 1)
          stop_spinner.call unless opts[:quiet]
          log.debug_log('FILES', "  ✓ #{name}: 1 file, #{rows.size - 1} lines") if opts[:verbose]
          return
        end
              
        unless Dir.exist?(path)
          stop_spinner.call
          log.warn "  Not found: #{path}"
          TripWire::TSV.write(tsv, [%w[timestamp severity message source]])
          return
        end
        
        rows, files = [%w[timestamp severity message source]], 0
        
        Dir.glob(File.join(path, '**', '*')).sort.each do |f|
          next unless File.file?(f)
          
          begin
            mt = File.mtime(f)
            next if !opts[:all_files] && !mt.between?(st, et)
            
            files += 1
            process_file(f, st, et, mt, rows)
          rescue => e
            next
          end
        end
        
        TripWire::TSV.write(tsv, rows)
        TripWire::Stats.instance.increment(:files, files)
        stop_spinner.call unless opts[:quiet]
        log.debug_log('FILES', "  ✓ #{name}: #{files} files, #{rows.size - 1} lines") if opts[:verbose]
      rescue => e
        log.error "#{name}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end
      
      private
      
      def self.process_file(file, st, et, mtime, rows, sniffer_mode = false)
        max_lines = sniffer_mode ? 500 : nil
        line_count = 0
        
        File.foreach(file, encoding: 'bom|utf-8') do |ln|
          line_count += 1
          break if max_lines && line_count > max_lines
          
          ts = TripWire::Utils.parse_timestamp(ln) || mtime
          # In sniffer mode, collect everything; otherwise filter by time
          next unless sniffer_mode || ts.between?(st, et)
          
          sev = TripWire::Utils.severity(ln)
          rows << [ts.strftime('%Y-%m-%d %H:%M:%S'), sev, TripWire::Utils.clean(ln), File.basename(file)]
          
          TripWire::Stats.instance.increment(:lines)
          TripWire::Stats.instance.increment(:err) if sev == 'ERROR'
          TripWire::Stats.instance.increment(:warn) if sev == 'WARN'
        end
      rescue
      end
    end
  end
end