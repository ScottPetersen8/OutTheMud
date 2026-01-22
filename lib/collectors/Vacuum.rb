module TripWire
  module Collectors
    module Vacuum
      # Target log types (expandable)
      LOG_PATTERNS = {
        'Datadog_Agent' => {
          names: ['datadog', 'dd-agent', 'dd'],
          patterns: ['*.log'],
          paths: ['C:/ProgramData/Datadog', 'C:/Program Files/Datadog', '/var/log/datadog', '/opt/datadog']
        },
        'PostgreSQL' => {
          names: ['postgresql', 'postgres', 'pgsql', 'pg'],
          patterns: ['*.log'],
          paths: ['C:/Program Files/PostgreSQL', 'C:/ProgramData/PostgreSQL', '/var/log/postgresql', '/var/lib/postgresql']
        }
        # Add more log types here as needed
      }.freeze
      
      def self.collect(st, et, root_dir, opts)
        log = TripWire::Logger.instance
        vacuum_dir = File.join(root_dir, 'Vacuum')
        FileUtils.mkdir_p(vacuum_dir)
        
        # Collect each log type individually (like Windows events)
        LOG_PATTERNS.each do |log_type, config|
          collect_log_type(log_type, config, st, et, vacuum_dir, opts)
        end
      end
      
      private
      
      def self.collect_log_type(log_type, config, st, et, vacuum_dir, opts)
        log = TripWire::Logger.instance
        log.info "#{log_type}..."
        
        stop_spinner = TripWire::Utils.spinner(log_type)
        
        # Find log directories and files
        log_files = find_logs_for_type(config)
        
        if log_files.empty?
          stop_spinner.call
          log.info "  ✗ Not found"
          # Still create empty TSV so you know we checked
          create_empty_tsv(vacuum_dir, log_type)
          return
        end
        
        # Consolidate all files into ONE TSV
        rows = [%w[timestamp severity message source file_path]]
        
        log_files.each do |file_path|
          file_rows = parse_log_file(file_path, st, et)
          rows.concat(file_rows)
        end
        
        # Write single consolidated TSV
        tsv_path = File.join(vacuum_dir, "#{log_type}.tsv")
        TripWire::TSV.write(tsv_path, rows)
        
        total_lines = rows.size - 1
        stop_spinner.call
        log.info "  ✓ #{log_files.size} files, #{total_lines} lines"
        
        TripWire::Stats.instance.increment(:files, log_files.size)
        TripWire::Stats.instance.increment(:lines, total_lines)
        
      rescue => e
        stop_spinner.call if stop_spinner
        log.error "#{log_type}: #{e.message}"
        TripWire::Stats.instance.increment(:err)
      end
      
      def self.find_logs_for_type(config)
        found = []
        
        # Search in known paths
        config[:paths].each do |base_path|
          next unless Dir.exist?(base_path)
          
          # Find matching directories
          config[:names].each do |search_name|
            find_matching_dirs(base_path, search_name, 0, 3).each do |dir|
              config[:patterns].each do |pattern|
                Dir.glob(File.join(dir, '**', pattern)).each do |file|
                  found << file if File.file?(file) && looks_like_log_file?(file)
                end
              end
            end
          end
        end
        
        found.uniq
      end
      
      def self.find_matching_dirs(base_path, search_name, depth, max_depth)
        return [] if depth > max_depth
        
        matching = []
        
        begin
          Dir.children(base_path).each do |entry|
            full_path = File.join(base_path, entry)
            next unless File.directory?(full_path)
            
            if entry.downcase.include?(search_name.downcase)
              matching << full_path
            end
            
            # Recurse
            matching.concat(find_matching_dirs(full_path, search_name, depth + 1, max_depth))
          end
        rescue
          # Access denied or other errors
        end
        
        matching
      end
      
      def self.parse_log_file(file_path, st, et)
        rows = []
        
        begin
          mt = File.mtime(file_path)
          
          File.open(file_path, 'r:bom|utf-8') do |f|
            f.each_line do |line|
              next if line.strip.empty?
              
              ts = TripWire::Utils.parse_timestamp(line) || mt
              next unless ts.between?(st, et)
              
              sev = TripWire::Utils.detect_severity(line)
              rows << [
                ts.strftime('%Y-%m-%d %H:%M:%S'),
                sev || 'INFO',
                TripWire::Utils.clean(line),
                File.basename(file_path),
                file_path
              ]
            end
          end
        rescue => e
          TripWire::Logger.instance.debug_log('VACUUM', "Error processing #{file_path}: #{e.message}")
        end
        
        rows
      end
      
      def self.create_empty_tsv(vacuum_dir, log_type)
        tsv_path = File.join(vacuum_dir, "#{log_type}.tsv")
        TripWire::TSV.write(tsv_path, [%w[timestamp severity message source file_path]])
      end
      
      def self.looks_like_log_file?(path)
        ext = File.extname(path).downcase
        return true if ['.log', '.txt'].include?(ext)
        
        basename = File.basename(path).downcase
        basename.include?('log')
      end
      
      # Legacy methods (kept for compatibility but unused)
      def self.discover_logs(opts)
        discoveries, search_paths = {}, get_search_paths(opts)
        log = TripWire::Logger.instance
        log.info "  Searching #{search_paths.size} paths..."
        
        search_paths.each do |base_path|
          next unless Dir.exist?(base_path)
          
          LOG_PATTERNS.each do |app_name, config|
            config[:names].each do |search_name|
              found = find_in_path(base_path, search_name, config, opts)
              if found && !found.empty?
                key = "#{app_name}_#{discoveries.size}"
                discoveries[key] = {
                  app: app_name,
                  category: config[:category],
                  path: found[:path],
                  files: found[:files],
                  size: found[:size]
                }
                log.info "  ✓ Found #{app_name} at #{found[:path]}"
              end
            end
          end
        end
        
        generic = find_generic_logs(search_paths, opts)
        unless generic.empty?
          discoveries['generic_logs'] = {
            app: 'generic',
            category: 'Unknown',
            path: 'multiple',
            files: generic,
            size: generic.inject(0) { |total, f| total + (File.size(f) rescue 0) }
          }
          log.info "  ✓ Found #{generic.size} generic log files"
        end
        
        discoveries
      end
      
      def self.get_search_paths(opts)
        return Array(opts[:vacuum_paths]) if opts[:vacuum_paths] && !opts[:vacuum_paths].empty?
        TripWire::PathResolver.windows? ? COMMON_PATHS[:windows] : COMMON_PATHS[:unix]
      end
      
      def self.find_in_path(base_path, search_name, config, opts)
        max_depth = opts[:vacuum_deep] ? 6 : 3
        queue = [[base_path, 0]]
        
        while !queue.empty?
          dir, depth = queue.shift
          next if depth > max_depth
          
          entries = Dir.children(dir) rescue next
          
          entries.each do |entry|
            full = File.join(dir, entry)
            next unless File.directory?(full)
            
            if entry.downcase.include?(search_name.downcase)
              files = collect_log_files(full, config[:patterns])
              unless files.empty?
                size = files.inject(0) { |total, f| total + (File.size(f) rescue 0) }
                return {path: full, files: files, size: size}
              end
            end
            
            queue << [full, depth + 1]
          end
        end
        
        nil
      rescue
        nil
      end
      
      def self.collect_log_files(dir, patterns)
        files = []
        patterns.each do |pattern|
          Dir.glob(File.join(dir, '**', pattern)).each do |f|
            files << f if File.file?(f) && is_log_file?(f)
          end rescue nil
        end
        files.uniq
      end
      
      def self.find_generic_logs(search_paths, opts)
        generic, max_files = [], opts[:vacuum_max_generic] || 100
        
        search_paths.each do |path|
          next unless Dir.exist?(path)
          
          Dir.glob(File.join(path, '*', '*.log')).each do |f|
            next unless File.file?(f) && is_log_file?(f)
            
            skip = LOG_PATTERNS.any? do |_, config|
              config[:names].any? { |name| f.downcase.include?(name.downcase) }
            end
            
            generic << f unless skip
            break if generic.size >= max_files
          end rescue nil
          
          break if generic.size >= max_files
        end
        
        generic
      end
      
      def self.is_log_file?(path)
        ext = File.extname(path).downcase
        return true if ['.log', '.txt'].include?(ext)
        
        basename = File.basename(path).downcase
        basename =~ /(log|audit|trace|debug|error|access)[\._-]/ || basename =~ /\d{4}-\d{2}-\d{2}/
      end
      
      def self.collect_source(source_name, info, st, et, root_dir, opts)
        log = TripWire::Logger.instance
        category_dir = File.join(root_dir, 'Vacuum', info[:category])
        source_dir = File.join(category_dir, source_name)
        FileUtils.mkdir_p(source_dir)
        
        rows, files_processed, lines_collected = [%w[timestamp severity message source file_path]], 0, 0
        
        info[:files].each do |file_path|
          begin
            mt = File.mtime(file_path)
            next if !opts[:all_files] && !mt.between?(st, et)
            
            file_rows = process_vacuum_file(file_path, st, et, mt)
            rows.concat(file_rows)
            files_processed += 1
            lines_collected += file_rows.size
          rescue
          end
        end
        
        tsv_path = File.join(source_dir, "#{source_name}.tsv")
        TripWire::TSV.write(tsv_path, rows)
        
        meta_path = File.join(source_dir, "metadata.txt")
        write_metadata(meta_path, source_name, info, files_processed, lines_collected)
        
        log.info "  #{source_name}: #{files_processed} files, #{lines_collected} lines"
        
        TripWire::Stats.instance.increment(:vacuum_sources)
        TripWire::Stats.instance.increment(:vacuum_files, files_processed)
        TripWire::Stats.instance.increment(:vacuum_lines, lines_collected)
      end
      
      def self.process_vacuum_file(file_path, st, et, mtime)
        rows = []
        File.foreach(file_path, encoding: 'bom|utf-8') do |ln|
          ts = TripWire::Utils.parse_timestamp(ln) || mtime
          next unless ts.between?(st, et)
          
          sev = TripWire::Utils.severity(ln)
          rows << [
            ts.strftime('%Y-%m-%d %H:%M:%S'),
            sev,
            TripWire::Utils.clean(ln),
            File.basename(file_path),
            file_path
          ]
        end
        rows
      rescue
        []
      end
      
      def self.write_metadata(path, source_name, info, files, lines)
        content = <<-META
Source: #{source_name}
Application: #{info[:app]}
Category: #{info[:category]}
Location: #{info[:path]}
Files Discovered: #{info[:files].size}
Files Processed: #{files}
Lines Collected: #{lines}
Total Size: #{format_size(info[:size])}

Files:
#{info[:files].map { |f| "  - #{f}" }.join("\n")}
        META
        
        File.write(path, content)
      end
      
      def self.generate_inventory(discoveries, root_dir)
        log = TripWire::Logger.instance
        inventory_path = File.join(root_dir, 'Vacuum', 'INVENTORY.txt')
        FileUtils.mkdir_p(File.dirname(inventory_path))
        
        by_category = {}
        discoveries.each do |source_name, info|
          by_category[info[:category]] ||= []
          by_category[info[:category]] << {name: source_name, info: info}
        end
        
        content = <<-HEADER
╔═══════════════════════════════════════════════════════════════════╗
║            TripWire VACUUM - System Log Inventory                 ║
╚═══════════════════════════════════════════════════════════════════╝
Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}
Total Sources: #{discoveries.size}
Total Files: #{discoveries.values.inject(0) { |total, v| total + v[:files].size }}
Total Size: #{format_size(discoveries.values.inject(0) { |total, v| total + v[:size] })}

═══════════════════════════════════════════════════════════════════

        HEADER
        
        by_category.keys.sort.each do |category|
          content << "\n## #{category}\n"
          content << "─" * 70 << "\n"
          
          by_category[category].each do |item|
            info = item[:info]
            content << sprintf("%-30s %6d files  %10s  %s\n",
                              item[:name],
                              info[:files].size,
                              format_size(info[:size]),
                              info[:path])
          end
        end
        
        content << "\n" << "═" * 70 << "\n"
        
        File.write(inventory_path, content)
        log.info "  Inventory: #{inventory_path}"
      end
      
      def self.format_size(bytes)
        return "0 B" if bytes == 0
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        exp = (Math.log(bytes) / Math.log(1024)).to_i
        exp = [exp, units.size - 1].min
        
        size = bytes.to_f / (1024 ** exp)
        sprintf("%.2f %s", size, units[exp])
      end
    end
  end
end