// internal/analyzer/engine.go
package analyzer

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"incident-analyzer/internal/config"
	"incident-analyzer/internal/storage"
)

type Engine struct {
	store  *storage.SQLiteStore
	config *config.Config
}

type AnalysisResult struct {
	Summary       Summary
	Timeline      []TimelineEvent
	Patterns      []PatternMatch
	Anomalies     []Anomaly
	RootCause     *RootCause
	Recommendations []string
	Statistics    Statistics
}

type Summary struct {
	TotalEvents   int64
	ErrorCount    int64
	WarningCount  int64
	ErrorRate     float64
	TimeRange     config.TimeRange
	Duration      time.Duration
	AffectedSources []string
}

type TimelineEvent struct {
	Timestamp time.Time
	Source    string
	Severity  string
	Message   string
	EventType string
}

type PatternMatch struct {
	Name        string
	Severity    string
	Description string
	Resolution  string
	Occurrences int
	FirstSeen   time.Time
	LastSeen    time.Time
	Events      []*storage.Event
}

type Anomaly struct {
	Type        string
	Timestamp   time.Time
	Severity    string
	Description string
	Value       float64
	Baseline    float64
	Deviation   float64
}

type RootCause struct {
	Pattern     string
	Confidence  float64
	Timestamp   time.Time
	Description string
	Evidence    []string
	Resolution  string
}

type Statistics struct {
	EventsBySource   map[string]int64
	EventsBySeverity map[string]int64
	TimeSeries       []storage.TimeSeriesPoint
	TopErrors        []ErrorSummary
}

type ErrorSummary struct {
	Message string
	Count   int
	Sources []string
}

type Baseline struct {
	AvgEventsPerMinute float64
	AvgErrorRate       float64
	StdDev             float64
	CommonPatterns     map[string]int
}

func NewEngine(store *storage.SQLiteStore, cfg *config.Config) *Engine {
	return &Engine{
		store:  store,
		config: cfg,
	}
}

func (e *Engine) Analyze(ctx context.Context, timeRange config.TimeRange, baseline *Baseline) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Summary: Summary{
			TimeRange: timeRange,
			Duration:  timeRange.End.Sub(timeRange.Start),
		},
	}

	// Get all events
	events, err := e.store.GetEvents(timeRange.Start, timeRange.End, "all")
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	// Build statistics
	result.Statistics = e.buildStatistics(events, timeRange)
	result.Summary.TotalEvents = int64(len(events))

	// Count errors and warnings
	for _, event := range events {
		switch event.Severity {
		case "ERROR", "FATAL", "CRITICAL":
			result.Summary.ErrorCount++
		case "WARN", "WARNING":
			result.Summary.WarningCount++
		}
	}

	// Calculate error rate
	if result.Summary.TotalEvents > 0 {
		result.Summary.ErrorRate = float64(result.Summary.ErrorCount) / float64(result.Summary.TotalEvents) * 100
	}

	// Detect patterns
	result.Patterns = e.detectPatterns(events)

	// Detect anomalies
	if baseline != nil {
		result.Anomalies = e.detectAnomalies(events, baseline, timeRange)
	}

	// Build timeline
	result.Timeline = e.buildTimeline(events, result.Patterns, result.Anomalies)

	// Determine root cause
	result.RootCause = e.determineRootCause(result.Patterns, result.Anomalies, events)

	// Generate recommendations
	result.Recommendations = e.generateRecommendations(result)

	// Get affected sources
	sources := make(map[string]bool)
	for _, event := range events {
		if event.Severity == "ERROR" || event.Severity == "FATAL" || event.Severity == "CRITICAL" {
			sources[event.Source] = true
		}
	}
	for source := range sources {
		result.Summary.AffectedSources = append(result.Summary.AffectedSources, source)
	}

	return result, nil
}

func (e *Engine) buildStatistics(events []*storage.Event, timeRange config.TimeRange) Statistics {
	stats := Statistics{
		EventsBySource:   make(map[string]int64),
		EventsBySeverity: make(map[string]int64),
	}

	// Count by source and severity
	errorMessages := make(map[string]*ErrorSummary)

	for _, event := range events {
		stats.EventsBySource[event.Source]++
		stats.EventsBySeverity[event.Severity]++

		// Track top errors
		if event.Severity == "ERROR" || event.Severity == "FATAL" || event.Severity == "CRITICAL" {
			// Normalize message (first 100 chars)
			msgKey := event.Message
			if len(msgKey) > 100 {
				msgKey = msgKey[:100]
			}

			if summary, exists := errorMessages[msgKey]; exists {
				summary.Count++
				if !contains(summary.Sources, event.Source) {
					summary.Sources = append(summary.Sources, event.Source)
				}
			} else {
				errorMessages[msgKey] = &ErrorSummary{
					Message: msgKey,
					Count:   1,
					Sources: []string{event.Source},
				}
			}
		}
	}

	// Get top 10 errors
	for _, summary := range errorMessages {
		stats.TopErrors = append(stats.TopErrors, *summary)
	}

	// Sort by count (simplified - use proper sorting)
	// sort.Slice(stats.TopErrors, func(i, j int) bool {
	//     return stats.TopErrors[i].Count > stats.TopErrors[j].Count
	// })

	if len(stats.TopErrors) > 10 {
		stats.TopErrors = stats.TopErrors[:10]
	}

	// Build time series
	timeSeries, _ := e.store.GetTimeSeriesData(timeRange.Start, timeRange.End, 1*time.Minute)
	stats.TimeSeries = timeSeries

	return stats
}

func (e *Engine) detectPatterns(events []*storage.Event) []PatternMatch {
	var matches []PatternMatch

	for _, patternConfig := range e.config.Patterns {
		var patternEvents []*storage.Event
		var firstSeen, lastSeen time.Time

		for _, event := range events {
			message := strings.ToLower(event.Message)
			matched := false

			for _, keyword := range patternConfig.Keywords {
				if strings.Contains(message, strings.ToLower(keyword)) {
					matched = true
					break
				}
			}

			if matched {
				patternEvents = append(patternEvents, event)
				if firstSeen.IsZero() || event.Timestamp.Before(firstSeen) {
					firstSeen = event.Timestamp
				}
				if lastSeen.IsZero() || event.Timestamp.After(lastSeen) {
					lastSeen = event.Timestamp
				}
			}
		}

		if len(patternEvents) > 0 {
			matches = append(matches, PatternMatch{
				Name:        patternConfig.Name,
				Severity:    patternConfig.Severity,
				Description: patternConfig.Description,
				Resolution:  patternConfig.Resolution,
				Occurrences: len(patternEvents),
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				Events:      patternEvents,
			})
		}
	}

	return matches
}

func (e *Engine) detectAnomalies(events []*storage.Event, baseline *Baseline, timeRange config.TimeRange) []Anomaly {
	var anomalies []Anomaly

	// Calculate current metrics
	duration := timeRange.End.Sub(timeRange.Start).Minutes()
	eventsPerMinute := float64(len(events)) / duration

	// Check for event rate spike
	if eventsPerMinute > baseline.AvgEventsPerMinute+(e.config.Thresholds.AnomalyStdDev*baseline.StdDev) {
		deviation := (eventsPerMinute - baseline.AvgEventsPerMinute) / baseline.AvgEventsPerMinute * 100
		anomalies = append(anomalies, Anomaly{
			Type:        "Event Rate Spike",
			Timestamp:   timeRange.Start,
			Severity:    "HIGH",
			Description: fmt.Sprintf("Event rate %.1f/min is %.1f%% above baseline (%.1f/min)", eventsPerMinute, deviation, baseline.AvgEventsPerMinute),
			Value:       eventsPerMinute,
			Baseline:    baseline.AvgEventsPerMinute,
			Deviation:   deviation,
		})
	}

	// Check for error rate increase
	errorCount := 0
	for _, event := range events {
		if event.Severity == "ERROR" || event.Severity == "FATAL" || event.Severity == "CRITICAL" {
			errorCount++
		}
	}
	currentErrorRate := float64(errorCount) / float64(len(events)) * 100

	if currentErrorRate > baseline.AvgErrorRate*e.config.Thresholds.ErrorRateMultiplier {
		anomalies = append(anomalies, Anomaly{
			Type:        "Error Rate Spike",
			Timestamp:   timeRange.Start,
			Severity:    "CRITICAL",
			Description: fmt.Sprintf("Error rate %.1f%% is %.1fx baseline (%.1f%%)", currentErrorRate, currentErrorRate/baseline.AvgErrorRate, baseline.AvgErrorRate),
			Value:       currentErrorRate,
			Baseline:    baseline.AvgErrorRate,
			Deviation:   currentErrorRate - baseline.AvgErrorRate,
		})
	}

	return anomalies
}

func (e *Engine) buildTimeline(events []*storage.Event, patterns []PatternMatch, anomalies []Anomaly) []TimelineEvent {
	var timeline []TimelineEvent

	// Add significant events
	for _, event := range events {
		if event.Severity == "ERROR" || event.Severity == "FATAL" || event.Severity == "CRITICAL" {
			timeline = append(timeline, TimelineEvent{
				Timestamp: event.Timestamp,
				Source:    event.Source,
				Severity:  event.Severity,
				Message:   event.Message,
				EventType: "error",
			})
		}
	}

	// Add pattern detections
	for _, pattern := range patterns {
		if pattern.Severity == "CRITICAL" {
			timeline = append(timeline, TimelineEvent{
				Timestamp: pattern.FirstSeen,
				Source:    "Analysis",
				Severity:  pattern.Severity,
				Message:   fmt.Sprintf("Pattern detected: %s (%d occurrences)", pattern.Name, pattern.Occurrences),
				EventType: "pattern",
			})
		}
	}

	// Add anomalies
	for _, anomaly := range anomalies {
		timeline = append(timeline, TimelineEvent{
			Timestamp: anomaly.Timestamp,
			Source:    "Analysis",
			Severity:  anomaly.Severity,
			Message:   anomaly.Description,
			EventType: "anomaly",
		})
	}

	// Sort by timestamp (simplified)
	return timeline
}

func (e *Engine) determineRootCause(patterns []PatternMatch, anomalies []Anomaly, events []*storage.Event) *RootCause {
	// Find the highest severity pattern with earliest occurrence
	var bestPattern *PatternMatch
	var earliestTime time.Time

	for i, pattern := range patterns {
		if pattern.Severity == "CRITICAL" {
			if bestPattern == nil || pattern.FirstSeen.Before(earliestTime) {
				bestPattern = &patterns[i]
				earliestTime = pattern.FirstSeen
			}
		}
	}

	if bestPattern == nil {
		return nil
	}

	// Calculate confidence based on evidence
	confidence := 0.5
	evidence := []string{
		fmt.Sprintf("%d occurrences of pattern '%s'", bestPattern.Occurrences, bestPattern.Name),
	}

	// Increase confidence with more occurrences
	if bestPattern.Occurrences > 10 {
		confidence += 0.2
	}
	if bestPattern.Occurrences > 50 {
		confidence += 0.1
	}

	// Increase confidence if anomalies detected
	if len(anomalies) > 0 {
		confidence += 0.1
		evidence = append(evidence, fmt.Sprintf("%d anomalies detected", len(anomalies)))
	}

	// Increase confidence if multiple sources affected
	sources := make(map[string]bool)
	for _, event := range bestPattern.Events {
		sources[event.Source] = true
	}
	if len(sources) > 2 {
		confidence += 0.1
		evidence = append(evidence, fmt.Sprintf("%d sources affected", len(sources)))
	}

	confidence = math.Min(confidence, 0.95)

	return &RootCause{
		Pattern:     bestPattern.Name,
		Confidence:  confidence,
		Timestamp:   bestPattern.FirstSeen,
		Description: bestPattern.Description,
		Evidence:    evidence,
		Resolution:  bestPattern.Resolution,
	}
}

func (e *Engine) generateRecommendations(result *AnalysisResult) []string {
	var recommendations []string

	// Based on root cause
	if result.RootCause != nil {
		recommendations = append(recommendations, "IMMEDIATE:")
		recommendations = append(recommendations, result.RootCause.Resolution)
	}

	// Based on affected sources
	if len(result.Summary.AffectedSources) > 3 {
		recommendations = append(recommendations, "")
		recommendations = append(recommendations, "CASCADING FAILURE DETECTED:")
		recommendations = append(recommendations, "  1. Focus on earliest failure point")
		recommendations = append(recommendations, "  2. Check dependencies between services")
		recommendations = append(recommendations, "  3. Review circuit breaker patterns")
	}

	// Based on error rate
	if result.Summary.ErrorRate > 10 {
		recommendations = append(recommendations, "")
		recommendations = append(recommendations, "HIGH ERROR RATE:")
		recommendations = append(recommendations, fmt.Sprintf("  • Error rate: %.1f%% (threshold: 10%%)", result.Summary.ErrorRate))
		recommendations = append(recommendations, "  • Consider rolling back recent deployments")
		recommendations = append(recommendations, "  • Enable debug logging")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No critical issues detected")
		recommendations = append(recommendations, "Review logs for any patterns or trends")
	}

	return recommendations
}

func LoadBaseline(path string) (*Baseline, error) {
	store, err := storage.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	stats, err := store.GetStats()
	if err != nil {
		return nil, err
	}

	duration := stats.EndTime.Sub(stats.StartTime).Minutes()
	eventsPerMinute := float64(stats.TotalEvents) / duration

	errorRate, _ := store.GetErrorRate(stats.StartTime, stats.EndTime)

	return &Baseline{
		AvgEventsPerMinute: eventsPerMinute,
		AvgErrorRate:       errorRate,
		StdDev:             eventsPerMinute * 0.2, // Simplified - calculate actual stddev
		CommonPatterns:     make(map[string]int),
	}, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}