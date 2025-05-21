package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
)

// Collector handles metric collection for the security system
type Collector struct {
	mutex sync.RWMutex

	// Event metrics
	totalEvents      int64
	eventsByType     map[string]int64
	eventsBySeverity map[string]int64

	// Anomaly metrics
	totalAnomalies  int64
	anomaliesByType map[string]int64
	anomalyScores   []float32

	// Performance metrics
	processingTimes []time.Duration

	// Time-based metrics
	hourlyEvents map[int]int64
	dailyEvents  map[string]int64
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		eventsByType:     make(map[string]int64),
		eventsBySeverity: make(map[string]int64),
		anomaliesByType:  make(map[string]int64),
		hourlyEvents:     make(map[int]int64),
		dailyEvents:      make(map[string]int64),
	}
}

// TrackEvent records metrics for a security event
func (c *Collector) TrackEvent(ctx context.Context, event *entity.SecurityEvent) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Increment total events
	c.totalEvents++

	// Track by type
	c.eventsByType[event.Action]++

	// Track by severity
	c.eventsBySeverity[event.Severity]++

	// Track by time
	hour := event.Timestamp.Hour()
	date := event.Timestamp.Format("2006-01-02")

	c.hourlyEvents[hour]++
	c.dailyEvents[date]++
}

// TrackAnomaly records metrics for an anomaly detection
func (c *Collector) TrackAnomaly(ctx context.Context, anomaly *entity.AnomalyResult) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Increment total anomalies
	c.totalAnomalies++

	// Track by type
	c.anomaliesByType[anomaly.AnomalyType]++

	// Track scores
	c.anomalyScores = append(c.anomalyScores, anomaly.Score)
}

// TrackProcessingTime records processing duration metrics
func (c *Collector) TrackProcessingTime(duration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.processingTimes = append(c.processingTimes, duration)
}

// GetStats retrieves current metrics
func (c *Collector) GetStats(ctx context.Context) map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return map[string]interface{}{
		"total_events":        c.totalEvents,
		"events_by_type":      c.eventsByType,
		"events_by_severity":  c.eventsBySeverity,
		"total_anomalies":     c.totalAnomalies,
		"anomalies_by_type":   c.anomaliesByType,
		"hourly_distribution": c.hourlyEvents,
		"daily_distribution":  c.dailyEvents,
	}
}

// GetPerformanceStats retrieves performance metrics
func (c *Collector) GetPerformanceStats(ctx context.Context) map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var totalTime time.Duration
	for _, t := range c.processingTimes {
		totalTime += t
	}

	avgTime := float64(totalTime) / float64(len(c.processingTimes))

	return map[string]interface{}{
		"average_processing_time_ms": avgTime / float64(time.Millisecond),
		"total_processed":            len(c.processingTimes),
	}
}
