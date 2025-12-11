module TripWire
  module Config
    PS_TIMEOUT = 60
    
    KEYWORDS = %w[shutdown crash panic fail error critical fatal exception].freeze
    
    SECURITY_IDS = [
      4625, 4648, 4672, 4720, 4722, 4724, 
      4732, 4735, 4738, 4740, 4756, 1102
    ].freeze
    
    DEFAULT_LOG_PATHS = {
      postgresql: 'C:/Program Files/PostgreSQL/11/data/log',
      datadog: 'C:/ProgramData/Datadog/logs'
    }.freeze
  end
end