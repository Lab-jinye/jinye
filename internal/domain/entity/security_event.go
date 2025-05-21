package entity

import (
	"time"

	"github.com/google/uuid"
)

// SecurityEvent represents a security-related event in the system
type SecurityEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip"`
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	User      string    `json:"user"`
	RawData   string    `json:"raw_data"`
	Severity  string    `json:"severity"`
	Labels    []string  `json:"labels"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewSecurityEvent creates a new security event with default values
func NewSecurityEvent() *SecurityEvent {
	now := time.Now()
	return &SecurityEvent{
		ID:        uuid.New().String(),
		Timestamp: now,
		CreatedAt: now,
		UpdatedAt: now,
		Severity:  "info",
		Labels:    make([]string, 0),
	}
}

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	Score       float32   `json:"score"`
	Timestamp   time.Time `json:"timestamp"`
	AnomalyType string    `json:"anomaly_type"`
	Confidence  float32   `json:"confidence"`
	Rules       []string  `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewAnomalyResult creates a new anomaly result with default values
func NewAnomalyResult(eventID string, score float32) *AnomalyResult {
	now := time.Now()
	return &AnomalyResult{
		ID:        uuid.New().String(),
		EventID:   eventID,
		Score:     score,
		Timestamp: now,
		CreatedAt: now,
		Rules:     make([]string, 0),
	}
}
