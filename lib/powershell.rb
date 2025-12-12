require 'tempfile'
require 'open3'
require 'timeout'

module TripWire
  module PowerShell
    def self.find
      %w[pwsh powershell.exe].each { |cmd| return cmd if system("where #{cmd} >nul 2>&1") }
      ps = File.join(ENV['WINDIR'] || 'C:/Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe')
      ps if File.exist?(ps)
    end
    
    def self.run(script)
      ps = find
      unless ps
        TripWire::Logger.instance.warn "PowerShell not found"
        TripWire::Stats.instance.increment(:ps_missing)
        return false
      end
      
      tf = Tempfile.new(['tw', '.ps1'])
      tf.write(script)
      tf.close
      
      begin
        Timeout.timeout(TripWire::Config::PS_TIMEOUT) do
          _, _, status = Open3.capture3(ps, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tf.path)
          unless status.success?
            TripWire::Logger.instance.warn "PowerShell failed (#{status.exitstatus})"
            TripWire::Stats.instance.increment(:ps_fail)
            return false
          end
          true
        end
      rescue Timeout::Error
        TripWire::Logger.instance.error "PowerShell timeout"
        TripWire::Stats.instance.increment(:ps_fail)
        false
      rescue => e
        TripWire::Logger.instance.error "PowerShell: #{e.message}"
        TripWire::Stats.instance.increment(:ps_fail)
        false
      ensure
        tf.unlink rescue nil
      end
    end
  end
end
