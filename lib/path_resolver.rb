# frozen_string_literal: true

module TripWire
  module PathResolver
    module_function

    def resolve(name:, configured:, defaults:, search_names:, log: nil)
      log ||= TripWire::Logger.instance
      log.log_enter('PATH', 'resolve', {name: name, configured: configured})
      log.info "Resolving path for #{name}..."
      log.log_path_resolution('START', "name=#{name}, configured=#{configured.inspect}")

      # 1) Configured path wins if it exists
      if configured && Dir.exist?(configured)
        log.info "  using configured: #{configured}"
        log.log_path_resolution('FOUND_CONFIGURED', configured)
        log.log_exit('PATH', 'resolve', configured)
        return configured
      elsif configured
        log.warn "  not found (configured): #{configured}"
        log.log_path_resolution('CONFIGURED_MISSING', configured)
      end

      # 2) Try known defaults
      log.log_path_resolution('TRY_DEFAULTS', "checking #{defaults.size} defaults")
      defaults.each_with_index do |p, idx|
        log.debug_log('PATH', "Default #{idx + 1}/#{defaults.size}: #{p}")
        if Dir.exist?(p)
          log.info "  using default: #{p}"
          log.log_path_resolution('FOUND_DEFAULT', p)
          log.log_exit('PATH', 'resolve', p)
          return p
        else
          log.debug_log('PATH', "Default not found: #{p}")
        end
      end

      # 3) Bounded discovery search
      log.log_path_resolution('START_DISCOVERY', "search_names=#{search_names.inspect}")
      candidate = discover(search_names, log: log)
      if candidate
        log.info "  discovered: #{candidate}"
        log.log_path_resolution('FOUND_DISCOVERED', candidate)
        log.log_exit('PATH', 'resolve', candidate)
        return candidate
      end

      log.warn "  no path found for #{name}"
      log.log_path_resolution('NOT_FOUND', name)
      log.log_exit('PATH', 'resolve', nil)
      nil
    end

    def discover(names, log: nil)
      log ||= TripWire::Logger.instance
      log.log_enter('PATH', 'discover', {names: names})
      
      roots = likely_roots
      names_i = names.map { |n| n.downcase }
      log.info "  searching roots: #{roots.join(', ')}"
      log.debug_log('PATH', "Search roots (#{roots.size}): #{roots.inspect}")
      log.debug_log('PATH', "Search names (case-insensitive): #{names_i.inspect}")

      roots.each_with_index do |root, idx|
        log.debug_log('PATH', "Checking root #{idx + 1}/#{roots.size}: #{root}")
        
        # quick existence check
        unless Dir.exist?(root)
          log.debug_log('PATH', "Root does not exist: #{root}")
          next
        end

        # breadth-first bounded search (max_depth to avoid expensive full scans)
        log.debug_log('PATH', "Searching in: #{root}")
        found = bfs_find_dir(root, names_i, max_depth: 4, log: log)
        if found
          log.debug_log('PATH', "FOUND in root #{root}: #{found}")
          log.log_exit('PATH', 'discover', found)
          return found
        end
      end
      
      log.debug_log('PATH', 'No path discovered')
      log.log_exit('PATH', 'discover', nil)
      nil
    end

    def likely_roots
      log = TripWire::Logger.instance
      
      if windows?
        log.debug_log('PATH', 'Platform: Windows')
        drives = []
        ('C'..'Z').each do |letter|
          path = "#{letter}:/"
          if Dir.exist?(path)
            drives << path
            log.debug_log('PATH', "Found drive: #{path}")
          end
        end
        
        # Add common program data locations
        extra = [
          ENV['ProgramData'] && File.join(ENV['ProgramData']),
          ENV['LOCALAPPDATA'] && File.join(ENV['LOCALAPPDATA']),
          ENV['APPDATA'] && File.join(ENV['APPDATA'])
        ].compact
        
        log.debug_log('PATH', "Extra paths from ENV: #{extra.inspect}")
        drives += extra
        drives.uniq
      else
        log.debug_log('PATH', 'Platform: Unix-like')
        roots = ['/', '/var', '/opt', '/usr/local', '/mnt', '/media', ENV['HOME']]
        roots.compact.uniq
      end
    end

    def windows?
      File::ALT_SEPARATOR == '\\' || RUBY_PLATFORM =~ /mswin|mingw|cygwin/i
    end

    def bfs_find_dir(start, names_i, max_depth:, log: nil)
      log ||= TripWire::Logger.instance
      log.log_enter('PATH', 'bfs_find_dir', {start: start, max_depth: max_depth})
      
      require 'find'
      queue = [[start, 0]]
      dirs_checked = 0

      until queue.empty?
        dir, depth = queue.shift
        
        if depth > max_depth
          log.debug_log('PATH', "Max depth reached at: #{dir}")
          next
        end

        begin
          entries = Dir.children(dir)
          dirs_checked += 1
          
          if dirs_checked % 100 == 0
            log.debug_log('PATH', "BFS progress: checked #{dirs_checked} directories")
          end
          
        rescue => e
          log.debug_log('PATH', "Cannot read dir: #{dir} | #{e.message}")
          next
        end

        # Check immediate subdirs for a match (case-insensitive)
        entries.each do |e|
          full = File.join(dir, e)
          next unless File.directory?(full)
          down = e.downcase

          names_i.each do |n|
            if down.include?(n)
              log.debug_log('PATH', "MATCH: '#{e}' contains '#{n}' at #{full}")
              log.log_exit('PATH', 'bfs_find_dir', full)
              return full
            end
          end

          # Queue deeper levels
          queue << [full, depth + 1]
        end
      end

      log.debug_log('PATH', "BFS complete: checked #{dirs_checked} directories, no match")
      log.log_exit('PATH', 'bfs_find_dir', nil)
      nil
    end
  end
end