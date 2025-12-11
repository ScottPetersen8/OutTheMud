
# frozen_string_literal: true

module TripWire
  module PathResolver
    module_function

    # Resolve a path for a product/service by:
    # 1) using a configured path if it exists,
    # 2) trying known defaults per OS,
    # 3) finally doing a bounded search of likely roots.
    #
    # name: "datadog" or "postgresql"
    # configured: a candidate path (String or nil)
    # defaults: array of known paths to try first
    # search_names: array of directory names to find (case-insensitive)
    # log: TripWire::Logger.instance (optional)
    def resolve(name:, configured:, defaults:, search_names:, log: nil)
      log&.info "Resolving path for #{name}..."

      # 1) Configured path wins if it exists
      if configured && Dir.exist?(configured)
        log&.info "  using configured: #{configured}"
        return configured
      elsif configured
        log&.warn "  not found (configured): #{configured}"
      end

      # 2) Try known defaults
      defaults.each do |p|
        if Dir.exist?(p)
          log&.info "  using default: #{p}"
          return p
        end
      end

      # 3) Bounded discovery search
      candidate = discover(search_names, log: log)
      if candidate
        log&.info "  discovered: #{candidate}"
        return candidate
      end

      log&.warn "  no path found for #{name}"
      nil
    end

    # --- internal helpers ---

    def discover(names, log: nil)
      roots = likely_roots
      names_i = names.map { |n| n.downcase }
      log&.info "  searching roots: #{roots.join(', ')}"

      roots.each do |root|
        # quick existence check
        next unless Dir.exist?(root)

        # breadth-first bounded search (max_depth to avoid expensive full scans)
        found = bfs_find_dir(root, names_i, max_depth: 4)
        return found if found
      end
      nil
    end

    # Enumerate likely roots cross-platform
    def likely_roots
      if windows?
        drives = []
        ('C'..'Z').each do |letter|
          path = "#{letter}:/"
          drives << path if Dir.exist?(path)
        end
        # Add common program data locations
        drives += [
          ENV['ProgramData'] && File.join(ENV['ProgramData']),
          ENV['LOCALAPPDATA'] && File.join(ENV['LOCALAPPDATA']),
          ENV['APPDATA'] && File.join(ENV['APPDATA'])
        ].compact
        drives.uniq
      else
        roots = ['/', '/var', '/opt', '/usr/local', '/mnt', '/media', ENV['HOME']]
        roots.compact.uniq
      end
    end

    def windows?
      File::ALT_SEPARATOR == '\\' || RUBY_PLATFORM =~ /mswin|mingw|cygwin/i
    end

    # Bounded breadth-first search for directories matching any name in names_i
    def bfs_find_dir(start, names_i, max_depth:)
      require 'find'
      queue = [[start, 0]]

      until queue.empty?
        dir, depth = queue.shift
        next if depth > max_depth

        begin
          entries = Dir.children(dir)
        rescue
          next
        end

        # Check immediate subdirs for a match (case-insensitive)
        entries.each do |e|
          full = File.join(dir, e)
          next unless File.directory?(full)
          down = e.downcase

          if names_i.any? { |n| down.include?(n) }
            return full
          end

          # Queue deeper levels
          queue << [full, depth + 1]
        end
      end

      nil
    end
  end
