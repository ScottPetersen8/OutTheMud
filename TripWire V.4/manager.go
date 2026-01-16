// internal/collectors/manager.go
package collectors

import (
	"context"
	"fmt"
	"sync"

	"incident-analyzer/internal/config"
	"incident-analyzer/internal/storage"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context, timeRange config.TimeRange) ([]*storage.Event, error)
}

type Manager struct {
	config     *config.Config
	store      *storage.SQLiteStore
	collectors []Collector
}

func NewManager(cfg *config.Config, store *storage.SQLiteStore) *Manager {
	m := &Manager{
		config: cfg,
		store:  store,
	}

	// Register collectors based on config
	if cfg.Collectors["windows_events"].Enabled {
		m.collectors = append(m.collectors, NewWindowsCollector(cfg))
	}
	if cfg.Collectors["iis"].Enabled {
		m.collectors = append(m.collectors, NewIISCollector(cfg))
	}
	if cfg.Collectors["application"].Enabled {
		m.collectors = append(m.collectors, NewFileCollector(cfg))
	}

	return m
}

func (m *Manager) CollectAll(ctx context.Context, timeRange config.TimeRange, sources []string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.collectors))
	results := make(chan CollectionResult, len(m.collectors))

	for _, collector := range m.collectors {
		// Skip if not in requested sources
		if !contains(sources, "all") && !contains(sources, collector.Name()) {
			continue
		}

		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()

			fmt.Printf("  ⏳ %-20s ", c.Name())
			
			events, err := c.Collect(ctx, timeRange)
			if err != nil {
				fmt.Printf("❌ Failed: %v\n", err)
				errChan <- fmt.Errorf("%s: %w", c.Name(), err)
				return
			}

			// Store events
			if err := m.store.InsertEvents(events); err != nil {
				fmt.Printf("❌ Storage failed: %v\n", err)
				errChan <- err
				return
			}

			results <- CollectionResult{
				Source: c.Name(),
				Count:  len(events),
			}
		}(collector)
	}

	// Wait for all collectors
	go func() {
		wg.Wait()
		close(errChan)
		close(results)
	}()

	// Print progress
	var totalEvents int
	for result := range results {
		fmt.Printf("✓ %-20s [████████████████] %d events\n", result.Source, result.Count)
		totalEvents += result.Count
	}

	// Check for errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("collection had %d error(s): %v", len(errors), errors[0])
	}

	fmt.Printf("\n📊 Total collected: %d events\n", totalEvents)
	return nil
}

type CollectionResult struct {
	Source string
	Count  int
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// internal/collectors/windows.go
package collectors

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"incident-analyzer/internal/config"
	"incident-analyzer/internal/storage"
)

type WindowsCollector struct {
	config *config.Config
}

func NewWindowsCollector(cfg *config.Config) *WindowsCollector {
	return &WindowsCollector{config: cfg}
}

func (w *WindowsCollector) Name() string {
	return "Windows Events"
}

func (w *WindowsCollector) Collect(ctx context.Context, timeRange config.TimeRange) ([]*storage.Event, error) {
	var allEvents []*storage.Event

	logs := w.config.Collectors["windows_events"].Paths
	for _, logName := range logs {
		events, err := w.collectLog(ctx, logName, timeRange)
		if err != nil {
			// Log warning but continue with other logs
			fmt.Printf("    ⚠️  %s: %v\n", logName, err)
			continue
		}
		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

func (w *WindowsCollector) collectLog(ctx context.Context, logName string, timeRange config.TimeRange) ([]*storage.Event, error) {
	// PowerShell script to get Windows events
	script := fmt.Sprintf(`
		$start = [datetime]'%s'
		$end = [datetime]'%s'
		Get-WinEvent -FilterHashtable @{
			LogName='%s'
			StartTime=$start
			EndTime=$end
		} -ErrorAction SilentlyContinue | 
		Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
		ConvertTo-Json -Compress
	`, timeRange.Start.Format(time.RFC3339), timeRange.End.Format(time.RFC3339), logName)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell failed: %w", err)
	}

	return parseWindowsEvents(output, logName)
}

func parseWindowsEvents(data []byte, source string) ([]*storage.Event, error) {
	// Parse JSON output from PowerShell
	// Simplified - in production use proper JSON parsing
	var events []*storage.Event
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		
		// Basic parsing - replace with proper JSON unmarshal
		event := &storage.Event{
			Source:    source,
			Timestamp: time.Now(), // Parse from JSON
			Severity:  "INFO",     // Map from LevelDisplayName
			Message:   line,
		}
		events = append(events, event)
	}

	return events, nil
}

// internal/collectors/files.go
package collectors

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"incident-analyzer/internal/config"
	"incident-analyzer/internal/storage"
)

type FileCollector struct {
	config *config.Config
}

func NewFileCollector(cfg *config.Config) *FileCollector {
	return &FileCollector{config: cfg}
}

func (f *FileCollector) Name() string {
	return "Application Logs"
}

func (f *FileCollector) Collect(ctx context.Context, timeRange config.TimeRange) ([]*storage.Event, error) {
	var allEvents []*storage.Event

	paths := f.config.Collectors["application"].Paths
	for _, basePath := range paths {
		events, err := f.collectFromPath(ctx, basePath, timeRange)
		if err != nil {
			continue // Skip paths that don't exist
		}
		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

func (f *FileCollector) collectFromPath(ctx context.Context, basePath string, timeRange config.TimeRange) ([]*storage.Event, error) {
	var events []*storage.Event

	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		if info.IsDir() {
			return nil
		}

		// Only process log files
		if !strings.HasSuffix(path, ".log") && !strings.HasSuffix(path, ".txt") {
			return nil
		}

		// Check if file was modified in time range
		if !info.ModTime().After(timeRange.Start) {
			return nil
		}

		fileEvents, err := f.parseLogFile(path, timeRange)
		if err == nil {
			events = append(events, fileEvents...)
		}

		return nil
	})

	return events, err
}

var (
	timestampRegex = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})`)
	severityRegex  = regexp.MustCompile(`\b(ERROR|FATAL|CRITICAL|WARN|WARNING|INFO|DEBUG)\b`)
)

func (f *FileCollector) parseLogFile(path string, timeRange config.TimeRange) ([]*storage.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []*storage.Event
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse timestamp
		tsMatch := timestampRegex.FindString(line)
		if tsMatch == "" {
			continue
		}

		ts, err := time.Parse("2006-01-02 15:04:05", strings.Replace(tsMatch, "T", " ", 1))
		if err != nil {
			continue
		}

		// Check if in time range
		if !ts.After(timeRange.Start) || !ts.Before(timeRange.End) {
			continue
		}

		// Parse severity
		severity := "INFO"
		if match := severityRegex.FindString(line); match != "" {
			severity = strings.ToUpper(match)
		}

		event := &storage.Event{
			Timestamp: ts,
			Source:    filepath.Base(path),
			Severity:  severity,
			Message:   line,
		}
		events = append(events, event)
	}

	return events, scanner.Err()
}

// internal/collectors/iis.go
package collectors

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"incident-analyzer/internal/config"
	"incident-analyzer/internal/storage"
)

type IISCollector struct {
	config *config.Config
}

func NewIISCollector(cfg *config.Config) *IISCollector {
	return &IISCollector{config: cfg}
}

func (i *IISCollector) Name() string {
	return "IIS Logs"
}

func (i *IISCollector) Collect(ctx context.Context, timeRange config.TimeRange) ([]*storage.Event, error) {
	var allEvents []*storage.Event

	paths := i.config.Collectors["iis"].Paths
	for _, basePath := range paths {
		events, err := i.collectFromPath(ctx, basePath, timeRange)
		if err != nil {
			continue
		}
		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

func (i *IISCollector) collectFromPath(ctx context.Context, basePath string, timeRange config.TimeRange) ([]*storage.Event, error) {
	var events []*storage.Event

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".log") {
			return nil
		}

		fileEvents, _ := i.parseIISLog(path, timeRange)
		events = append(events, fileEvents...)

		return nil
	})

	return events, nil
}

func (i *IISCollector) parseIISLog(path string, timeRange config.TimeRange) ([]*storage.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []*storage.Event
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse IIS W3C format: date time s-ip cs-method cs-uri-stem ...
		timestamp, err := time.Parse("2006-01-02 15:04:05", fields[0]+" "+fields[1])
		if err != nil {
			continue
		}

		if !timestamp.After(timeRange.Start) || !timestamp.Before(timeRange.End) {
			continue
		}

		// Determine severity based on status code
		severity := "INFO"
		if len(fields) > 10 {
			status := fields[10]
			if strings.HasPrefix(status, "5") {
				severity = "ERROR"
			} else if strings.HasPrefix(status, "4") {
				severity = "WARN"
			}
		}

		event := &storage.Event{
			Timestamp: timestamp,
			Source:    "IIS",
			Severity:  severity,
			Message:   line,
		}
		events = append(events, event)
	}

	return events, scanner.Err()
}