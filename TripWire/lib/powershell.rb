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
      stdout, stderr, status = nil, nil, nil
      
      begin
        stdout, stderr, status = Open3.capture3(ps, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tf.path)
      rescue IOError => e
        TripWire::Logger.instance.warn "PowerShell IOError (script may have exited early): #{e.message}"
        # Don't treat as total failure - the script may have written output before exiting
        return true
      end
      
      # Log any output for debugging
      if stdout && !stdout.empty?
        TripWire::Logger.instance.debug "PS STDOUT: #{stdout}"
      end
      if stderr && !stderr.empty?
        TripWire::Logger.instance.warn "PS STDERR: #{stderr}"
      end
        
          unless status.success?
            TripWire::Logger.instance.warn "PowerShell exit code: #{status.exitstatus}"
            # Exit code 2 = access denied (from our updated script)
            # Exit code 0 or nil = might still have written output
            return status.exitstatus == 0 || status.exitstatus.nil?
          end
          true
        end
      rescue Timeout::Error
        TripWire::Logger.instance.error "PowerShell timeout (#{TripWire::Config::PS_TIMEOUT}s)"
        TripWire::Stats.instance.increment(:ps_fail)
        false
      rescue => e
        TripWire::Logger.instance.error "PowerShell error: #{e.class} - #{e.message}"
        TripWire::Logger.instance.debug e.backtrace.join("\n")
        TripWire::Stats.instance.increment(:ps_fail)
        false
      ensure
        tf.unlink rescue nil
      end
    end
  end
end