// internal/config/config.go
package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Collectors map[string]CollectorConfig `yaml:"collectors"`
	Patterns   []PatternConfig            `yaml:"patterns"`
	Thresholds ThresholdConfig            `yaml:"thresholds"`
}

type CollectorConfig struct {
	Enabled bool              `yaml:"enabled"`
	Paths   []string          `yaml:"paths"`
	Timeout time.Duration     `yaml:"timeout"`
	Options map[string]string `yaml:"options"`
}

type PatternConfig struct {
	Name        string   `yaml:"name"`
	Keywords    []string `yaml:"keywords"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Resolution  string   `yaml:"resolution"`
}

type ThresholdConfig struct {
	ErrorRateMultiplier float64 `yaml:"error_rate_multiplier"`
	AnomalyStdDev       float64 `yaml:"anomaly_std_dev"`
	MinConfidence       float64 `yaml:"min_confidence"`
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

func LoadConfig() *Config {
	cfg := defaultConfig()

	// Try to load from file
	configPaths := []string{
		"config.yml",
		"config.yaml",
		filepath.Join(os.Getenv("HOME"), ".incident-analyzer", "config.yml"),
		"/etc/incident-analyzer/config.yml",
	}

	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			if err := yaml.Unmarshal(data, cfg); err == nil {
				return cfg
			}
		}
	}

	return cfg
}

func defaultConfig() *Config {
	return &Config{
		Collectors: map[string]CollectorConfig{
			"windows_events": {
				Enabled: true,
				Paths:   []string{"System", "Application", "Security"},
				Timeout: 5 * time.Minute,
			},
			"iis": {
				Enabled: true,
				Paths: []string{
					`C:\inetpub\logs\LogFiles`,
					`D:\inetpub\logs\LogFiles`,
				},
				Timeout: 2 * time.Minute,
			},
			"sql_server": {
				Enabled: true,
				Paths: []string{
					`C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log`,
				},
				Timeout: 2 * time.Minute,
			},
			"application": {
				Enabled: true,
				Paths: []string{
					`C:\Logs`,
					`D:\Logs`,
					`C:\ProgramData\Datadog\logs`,
				},
				Timeout: 3 * time.Minute,
			},
		},
		Patterns: []PatternConfig{
			{
				Name:        "Database Connection Pool Exhaustion",
				Keywords:    []string{"connection pool", "too many connections", "pool exhausted"},
				Severity:    "CRITICAL",
				Description: "Database connection pool is full",
				Resolution:  "1. Increase pool size\n2. Check for connection leaks\n3. Review recent deployments",
			},
			{
				Name:        "Out of Memory",
				Keywords:    []string{"out of memory", "oom", "heap", "memory exhausted"},
				Severity:    "CRITICAL",
				Description: "Application or system running out of memory",
				Resolution:  "1. Check memory usage trends\n2. Look for memory leaks\n3. Increase available memory",
			},
			{
				Name:        "Disk Space Exhausted",
				Keywords:    []string{"disk full", "no space left", "disk quota exceeded"},
				Severity:    "CRITICAL",
				Description: "Disk space has been exhausted",
				Resolution:  "1. Clean up old logs\n2. Increase disk capacity\n3. Enable log rotation",
			},
			{
				Name:        "Network Timeout",
				Keywords:    []string{"timeout", "connection refused", "network unreachable"},
				Severity:    "HIGH",
				Description: "Network connectivity issues detected",
				Resolution:  "1. Check network connectivity\n2. Review firewall rules\n3. Check DNS resolution",
			},
			{
				Name:        "Authentication Failure",
				Keywords:    []string{"authentication failed", "unauthorized", "access denied", "invalid credentials"},
				Severity:    "HIGH",
				Description: "Authentication or authorization failures",
				Resolution:  "1. Verify credentials\n2. Check certificate expiry\n3. Review IAM policies",
			},
			{
				Name:        "Deadlock Detected",
				Keywords:    []string{"deadlock", "lock timeout", "waiting for lock"},
				Severity:    "HIGH",
				Description: "Database deadlock condition",
				Resolution:  "1. Review transaction isolation\n2. Optimize query patterns\n3. Check for long-running transactions",
			},
		},
		Thresholds: ThresholdConfig{
			ErrorRateMultiplier: 3.0,
			AnomalyStdDev:       3.0,
			MinConfidence:       0.7,
		},
	}
}