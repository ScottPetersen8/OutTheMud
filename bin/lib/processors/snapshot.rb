module TripWire
  module Processors
    module Snapshot
      def self.capture(dir)
        TripWire::Logger.instance.info "Snapshot..."
        
        ps = <<~PS
          Get-CimInstance Win32_LogicalDisk | ConvertTo-Csv -Delimiter "`t" -NoType | Out-File '#{File.join(dir, 'disk.tsv')}' -Encoding utf8 -Force
          Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Csv -Delimiter "`t" -NoType | Out-File '#{File.join(dir, 'mem.tsv')}' -Encoding utf8 -Force
        PS
        
        stop = TripWire::Utils.spinner("Snapshot")
        TripWire::PowerShell.run(ps)
        stop.call
        
        TripWire::Logger.instance.info "  ✓ Done"
      end
    end
  end
end
