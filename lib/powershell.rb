require 'tempfile'
require 'open3'
require 'timeout'

module TripWire
  module PowerShell
    def self.find
      log = TripWire::Logger.instance
      log.log_enter('PWSH', 'find')
      
      %w[pwsh powershell.exe].each do |cmd|
        log.debug_log('PWSH', "Checking for: #{cmd}")
        if system("where #{cmd} >nul 2>&1")
          log.debug_log('PWSH', "FOUND: #{cmd}")
          log.log_exit('PWSH', 'find', cmd)
          return cmd
        end
      end
      
      ps = File.join(ENV['WINDIR'] || 'C:/Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe')
      log.debug_log('PWSH', "Checking fallback path: #{ps}")
      
      if File.exist?(ps)
        log.debug_log('PWSH', "FOUND at fallback: #{ps}")
        log.log_exit('PWSH', 'find', ps)
        return ps
      end
      
      log.debug_log('PWSH', 'PowerShell NOT FOUND')
      log.log_exit('PWSH', 'find', nil)
      nil
    end
    
    def self.run(script)
      log = TripWire::Logger.instance
      log.log_enter('PWSH', 'run', {script_length: script.length})
      
      ps = find
      unless ps
        log.warn "PowerShell not found"
        log.debug_log('PWSH', 'Cannot execute: PowerShell not found')
        TripWire::Stats.instance.increment(:ps_missing)
        log.log_exit('PWSH', 'run', false)
        return false
      end
      
      tf = Tempfile.new(['tw', '.ps1'])
      tf.write(script)
      tf.close
      
      log.log_file_op('CREATE_TEMP', tf.path, {size: script.length})
      log.debug_log('PWSH', "Temp script: #{tf.path}")
      
      begin
        log.debug_log('PWSH', "Executing with timeout: #{TripWire::Config::PS_TIMEOUT}s")
        start_time = Time.now
        
        Timeout.timeout(TripWire::Config::PS_TIMEOUT) do
          stdout, stderr, status = Open3.capture3(ps, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tf.path)
          elapsed = Time.now - start_time
          
          log.debug_log('PWSH', "Execution completed in #{sprintf('%.2f', elapsed)}s")
          log.debug_log('PWSH', "Exit status: #{status.exitstatus}")
          log.debug_log('PWSH', "STDOUT (#{stdout.length} bytes): #{stdout[0...500]}") unless stdout.empty?
          log.debug_log('PWSH', "STDERR (#{stderr.length} bytes): #{stderr[0...500]}") unless stderr.empty?
          
          unless status.success?
            log.warn "PowerShell failed (#{status.exitstatus})"
            log.log_powershell(script, false, {
              exitstatus: status.exitstatus,
              elapsed: elapsed,
              stdout_length: stdout.length,
              stderr_length: stderr.length
            })
            TripWire::Stats.instance.increment(:ps_fail)
            log.log_exit('PWSH', 'run', false)
            return false
          end
          
          log.log_powershell(script, true, {
            exitstatus: status.exitstatus,
            elapsed: elapsed,
            stdout_length: stdout.length
          })
          log.log_exit('PWSH', 'run', true)
          true
        end
      rescue Timeout::Error
        elapsed = Time.now - start_time
        log.error "PowerShell timeout"
        log.debug_log('PWSH', "TIMEOUT after #{sprintf('%.2f', elapsed)}s")
        log.log_powershell(script, false, {error: 'timeout', elapsed: elapsed})
        TripWire::Stats.instance.increment(:ps_fail)
        log.log_exit('PWSH', 'run', false)
        false
      rescue => e
        log.error "PowerShell: #{e.message}"
        log.debug_log('PWSH', "ERROR: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}")
        log.log_powershell(script, false, {error: e.message, error_class: e.class.name})
        TripWire::Stats.instance.increment(:ps_fail)
        log.log_exit('PWSH', 'run', false)
        false
      ensure
        begin
          tf.unlink
          log.log_file_op('DELETE_TEMP', tf.path)
        rescue
          log.debug_log('PWSH', "Failed to delete temp file: #{tf.path}")
        end
      end
    end
  end
end