package repository

import (
	"context"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
)

// EventRepository defines the interface for security event storage
type EventRepository interface {
	// SaveEvent saves a security event to the repository
	SaveEvent(ctx context.Context, event *entity.SecurityEvent) error

	// FindEventByID retrieves a security event by its ID
	FindEventByID(ctx context.Context, id string) (*entity.SecurityEvent, error)

	// FindEventsByTimeRange retrieves security events within a time range
	FindEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*entity.SecurityEvent, error)

	// SaveAnomaly saves an anomaly detection result
	SaveAnomaly(ctx context.Context, anomaly *entity.AnomalyResult) error

	// FindAnomaliesByEventID retrieves anomaly results for a specific event
	FindAnomaliesByEventID(ctx context.Context, eventID string) ([]*entity.AnomalyResult, error)
}

// VectorRepository defines the interface for vector storage and similarity search
type VectorRepository interface {
	// SaveEventVector saves a vector representation of an event
	SaveEventVector(ctx context.Context, eventID string, vector []float32) error

	// GetEventVector retrieves the vector representation of an event
	GetEventVector(ctx context.Context, eventID string) ([]float32, error)

	// FindSimilarEvents finds similar events based on vector similarity
	FindSimilarEvents(ctx context.Context, vector []float32, limit int) ([]string, error)

	// UpdateEventVector updates the vector representation of an event
	UpdateEventVector(ctx context.Context, eventID string, vector []float32) error
}

// CacheRepository defines the interface for caching operations
type CacheRepository interface {
	// Set stores a value in the cache with an expiration time
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (interface{}, error)

	// Delete removes a value from the cache
	Delete(ctx context.Context, key string) error
}
