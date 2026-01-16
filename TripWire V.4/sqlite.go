// internal/storage/sqlite.go
package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Event struct {
	ID        int64
	Timestamp time.Time
	Source    string
	Severity  string
	Message   string
	EventID   string
	Metadata  map[string]string
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}
	if err := store.initialize(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) initialize() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		source TEXT NOT NULL,
		severity TEXT NOT NULL,
		message TEXT,
		event_id TEXT,
		raw_data TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_source ON events(source);
	CREATE INDEX IF NOT EXISTS idx_severity ON events(severity);
	CREATE INDEX IF NOT EXISTS idx_source_severity ON events(source, severity);

	CREATE TABLE IF NOT EXISTS metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		metric_name TEXT NOT NULL,
		value REAL NOT NULL,
		source TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name);

	CREATE TABLE IF NOT EXISTS patterns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern_name TEXT NOT NULL,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		count INTEGER DEFAULT 1,
		severity TEXT
	);
	`

	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteStore) InsertEvent(event *Event) error {
	query := `
	INSERT INTO events (timestamp, source, severity, message, event_id)
	VALUES (?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query, event.Timestamp, event.Source, event.Severity, event.Message, event.EventID)
	return err
}

func (s *SQLiteStore) InsertEvents(events []*Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events (timestamp, source, severity, message, event_id)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, event := range events {
		_, err := stmt.Exec(event.Timestamp, event.Source, event.Severity, event.Message, event.EventID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetEvents(start, end time.Time, source string) ([]*Event, error) {
	query := `
	SELECT id, timestamp, source, severity, message, event_id
	FROM events
	WHERE timestamp BETWEEN ? AND ?
	`
	args := []interface{}{start, end}

	if source != "" && source != "all" {
		query += " AND source = ?"
		args = append(args, source)
	}

	query += " ORDER BY timestamp ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event := &Event{}
		err := rows.Scan(&event.ID, &event.Timestamp, &event.Source, &event.Severity, &event.Message, &event.EventID)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

func (s *SQLiteStore) GetEventCount(start, end time.Time) (int64, error) {
	var count int64
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM events
		WHERE timestamp BETWEEN ? AND ?
	`, start, end).Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetEventsBySeverity(start, end time.Time) (map[string]int64, error) {
	rows, err := s.db.Query(`
		SELECT severity, COUNT(*) as count
		FROM events
		WHERE timestamp BETWEEN ? AND ?
		GROUP BY severity
	`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[severity] = count
	}

	return counts, rows.Err()
}

func (s *SQLiteStore) GetEventsBySource(start, end time.Time) (map[string]int64, error) {
	rows, err := s.db.Query(`
		SELECT source, COUNT(*) as count
		FROM events
		WHERE timestamp BETWEEN ? AND ?
		GROUP BY source
		ORDER BY count DESC
	`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var source string
		var count int64
		if err := rows.Scan(&source, &count); err != nil {
			return nil, err
		}
		counts[source] = count
	}

	return counts, rows.Err()
}

func (s *SQLiteStore) GetErrorRate(start, end time.Time) (float64, error) {
	var total, errors int64

	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM events WHERE timestamp BETWEEN ? AND ?
	`, start, end).Scan(&total)
	if err != nil {
		return 0, err
	}

	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM events 
		WHERE timestamp BETWEEN ? AND ?
		AND (severity = 'ERROR' OR severity = 'FATAL' OR severity = 'CRITICAL')
	`, start, end).Scan(&errors)
	if err != nil {
		return 0, err
	}

	if total == 0 {
		return 0, nil
	}

	return float64(errors) / float64(total) * 100, nil
}

func (s *SQLiteStore) GetTimeSeriesData(start, end time.Time, bucketSize time.Duration) ([]TimeSeriesPoint, error) {
	bucketSeconds := int(bucketSize.Seconds())
	
	rows, err := s.db.Query(`
		SELECT 
			(strftime('%s', timestamp) / ? * ?) as bucket,
			COUNT(*) as total,
			SUM(CASE WHEN severity IN ('ERROR', 'FATAL', 'CRITICAL') THEN 1 ELSE 0 END) as errors
		FROM events
		WHERE timestamp BETWEEN ? AND ?
		GROUP BY bucket
		ORDER BY bucket
	`, bucketSeconds, bucketSeconds, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TimeSeriesPoint
	for rows.Next() {
		var bucketTime int64
		var total, errors int64
		if err := rows.Scan(&bucketTime, &total, &errors); err != nil {
			return nil, err
		}

		points = append(points, TimeSeriesPoint{
			Timestamp: time.Unix(bucketTime, 0),
			Total:     total,
			Errors:    errors,
		})
	}

	return points, rows.Err()
}

type TimeSeriesPoint struct {
	Timestamp time.Time
	Total     int64
	Errors    int64
}

func (s *SQLiteStore) SearchMessages(pattern string, start, end time.Time, limit int) ([]*Event, error) {
	query := `
	SELECT id, timestamp, source, severity, message, event_id
	FROM events
	WHERE timestamp BETWEEN ? AND ?
	AND message LIKE ?
	ORDER BY timestamp DESC
	LIMIT ?
	`

	rows, err := s.db.Query(query, start, end, "%"+pattern+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event := &Event{}
		err := rows.Scan(&event.ID, &event.Timestamp, &event.Source, &event.Severity, &event.Message, &event.EventID)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

func (s *SQLiteStore) InsertMetric(timestamp time.Time, name string, value float64, source string) error {
	_, err := s.db.Exec(`
		INSERT INTO metrics (timestamp, metric_name, value, source)
		VALUES (?, ?, ?, ?)
	`, timestamp, name, value, source)
	return err
}

func (s *SQLiteStore) GetStats() (*Stats, error) {
	stats := &Stats{}

	// Total events
	err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&stats.TotalEvents)
	if err != nil {
		return nil, err
	}

	// Time range
	err = s.db.QueryRow(`
		SELECT MIN(timestamp), MAX(timestamp) FROM events
	`).Scan(&stats.StartTime, &stats.EndTime)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Sources
	rows, err := s.db.Query("SELECT DISTINCT source FROM events")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return nil, err
		}
		stats.Sources = append(stats.Sources, source)
	}

	return stats, nil
}

type Stats struct {
	TotalEvents int64
	StartTime   time.Time
	EndTime     time.Time
	Sources     []string
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Vacuum() error {
	_, err := s.db.Exec("VACUUM")
	return err
}