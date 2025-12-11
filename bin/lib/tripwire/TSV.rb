require 'fileutils'

module TripWire
  module TSV
    def self.write(file, rows)
      FileUtils.mkdir_p(File.dirname(file))
      File.open(file, 'w:UTF-8') do |f|
        rows.each { |r| f.puts r.map { |v| v.to_s.gsub(/[\t\r\n]+/, ' ').strip }.join("\t") }
      end
    rescue => e
      TripWire::Logger.instance.error "TSV write failed: #{e.message}"
      false
    end
    
    def self.each(file)
      return unless File.exist?(file) && block_given?
      
      File.open(file, 'r:bom|utf-8') do |f|
        headers = f.readline.strip.split("\t", -1) rescue return
        f.each_line { |ln| yield Hash[headers.zip(ln.strip.split("\t", -1))] unless ln.strip.empty? }
      end
    rescue => e
      TripWire::Logger.instance.error "TSV read: #{e.message}"
    end
  end
end