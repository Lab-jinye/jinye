package log

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jinye/securityai/internal/ai/anomaly"
	"github.com/jinye/securityai/internal/domain/entity"
	"github.com/jinye/securityai/internal/domain/repository"
)

// LogProcessor handles log processing and analysis
type LogProcessor struct {
	detector   *anomaly.AnomalyDetector
	repository repository.EventRepository
	cache      repository.CacheRepository
	enricher   *LogEnricher
}

// NewLogProcessor creates a new log processor instance
func NewLogProcessor(
	detector *anomaly.AnomalyDetector,
	repository repository.EventRepository,
	cache repository.CacheRepository,
	enricher *LogEnricher,
) *LogProcessor {
	return &LogProcessor{
		detector:   detector,
		repository: repository,
		cache:      cache,
		enricher:   enricher,
	}
}

// ProcessLog processes a single log entry
func (p *LogProcessor) ProcessLog(ctx context.Context, rawLog string) error {
	// Parse log entry
	event, err := p.parseLog(rawLog)
	if err != nil {
		return err
	}

	// Enrich log data
	if err := p.enricher.Enrich(ctx, event); err != nil {
		return err
	}

	// Check cache for recent similar events
	cacheKey := p.generateCacheKey(event)
	if _, err := p.cache.Get(ctx, cacheKey); err == nil {
		// Similar event recently processed, skip analysis
		return nil
	}

	// Process event for anomalies
	anomalies, err := p.detector.ProcessEvents(ctx, []*entity.SecurityEvent{event})
	if err != nil {
		return err
	}

	// Save event
	if err := p.repository.SaveEvent(ctx, event); err != nil {
		return err
	}

	// Cache event signature
	p.cache.Set(ctx, cacheKey, true, 5*time.Minute)

	// Handle detected anomalies
	if len(anomalies) > 0 {
		for _, anomaly := range anomalies {
			if err := p.repository.SaveAnomaly(ctx, anomaly); err != nil {
				return err
			}
		}
	}

	return nil
}

// BatchProcessLogs processes multiple log entries in batch
func (p *LogProcessor) BatchProcessLogs(ctx context.Context, logs []string) error {
	events := make([]*entity.SecurityEvent, 0, len(logs))

	for _, log := range logs {
		event, err := p.parseLog(log)
		if err != nil {
			continue
		}

		if err := p.enricher.Enrich(ctx, event); err != nil {
			continue
		}

		events = append(events, event)
	}

	if len(events) > 0 {
		if _, err := p.detector.ProcessEvents(ctx, events); err != nil {
			return err
		}
	}

	return nil
}

// parseLog parses a raw log entry into a SecurityEvent
func (p *LogProcessor) parseLog(rawLog string) (*entity.SecurityEvent, error) {
	event := entity.NewSecurityEvent()
	event.RawData = rawLog

	// TODO: Implement actual log parsing logic based on your log format
	// This is a placeholder implementation
	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(rawLog), &logData); err != nil {
		return nil, err
	}

	// Map fields from logData to event
	if timestamp, ok := logData["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
			event.Timestamp = t
		}
	}

	if sourceIP, ok := logData["source_ip"].(string); ok {
		event.SourceIP = sourceIP
	}

	// ... map other fields

	return event, nil
}

// generateCacheKey generates a cache key for deduplication
func (p *LogProcessor) generateCacheKey(event *entity.SecurityEvent) string {
	return "event:" + event.SourceIP + ":" + event.DestIP + ":" +
		event.Protocol + ":" + string(event.Timestamp.Unix())
}
