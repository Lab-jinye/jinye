package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"context"

	"github.com/jinye/securityai/internal/ai/anomaly" // Assuming this is the package for SimpleAnomalyDetector
	"github.com/jinye/securityai/api/handler"
	"github.com/jinye/securityai/internal/ai/anomaly"
	"github.com/jinye/securityai/internal/service/log"
)

func main() {
	ctx := context.Background()

	// 2. Create simple in-memory implementations for repositories and enricher
	eventRepo := NewInMemoryEventRepository()
	cacheRepo := NewInMemoryCacheRepository()
	enricher := NewInMemoryLogEnricher()

	// 3. Initialize SimpleAnomalyDetector
	// Assuming anomaly.SimpleAnomalyDetector exists and has a NewSimpleAnomalyDetector constructor
	// If the existing anomaly.AnomalyDetector in processor.go is meant to be SimpleAnomalyDetector,
	// we need to make sure its constructor matches. For now, let's assume NewSimpleAnomalyDetector exists.
	detector := anomaly.NewSimpleAnomalyDetector() // Assuming this constructor exists

	// 4. Create a LogProcessor instance
	logProcessor := log.NewLogProcessor(detector, eventRepo, cacheRepo, enricher)

	// 5. Create some sample JSON log strings
	sampleLogs := []string{
		`{"timestamp": "2023-10-27T10:00:00Z", "source_ip": "192.168.1.10", "dest_ip": "10.0.0.1", "protocol": "TCP", "event_type": "connection", "description": "Successful connection"}`,
		`{"timestamp": "2023-10-27T10:00:05Z", "source_ip": "192.168.1.10", "dest_ip": "10.0.0.2", "protocol": "UDP", "event_type": "connection", "description": "Successful connection"}`,
		`{"timestamp": "2023-10-27T10:00:10Z", "source_ip": "192.168.1.11", "dest_ip": "10.0.0.3", "protocol": "TCP", "event_type": "login_fail", "description": "Authentication failure"}`,
		`{"timestamp": "2023-10-27T10:00:12Z", "source_ip": "192.168.1.11", "dest_ip": "10.0.0.3", "protocol": "TCP", "event_type": "login_fail", "description": "Authentication failure"}`,
		`{"timestamp": "2023-10-27T10:00:15Z", "source_ip": "192.168.1.11", "dest_ip": "10.0.0.3", "protocol": "TCP", "event_type": "login_fail", "description": "Authentication failure"}`,
		// Add more logs to trigger the simple anomaly detector (e.g., same IP appearing many times)
		`{"timestamp": "2023-10-27T10:01:00Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.5", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:01Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.6", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:02Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.7", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:03Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.8", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:04Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.9", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:05Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.10", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:06Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.11", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:07Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.12", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:08Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.13", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:09Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.14", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`,
		`{"timestamp": "2023-10-27T10:01:10Z", "source_ip": "172.16.0.100", "dest_ip": "10.0.1.15", "protocol": "TCP", "event_type": "port_scan", "description": "Attempted port scan"}`, // This one should trigger anomaly
	}

	// 6. Iterate through the sample logs and process them
	log.Println("Processing sample logs...")
	for _, rawLog := range sampleLogs {
		err := logProcessor.ProcessLog(ctx, rawLog)
		if err != nil {
			log.Printf("Error processing log: %v", err)
		}
	}

	// 7. Print out the saved events and detected anomalies
	log.Println("\n--- Processed Results ---")
	fmt.Printf("Saved Events (%d):\n", len(eventRepo.events))
	for _, event := range eventRepo.events {
		fmt.Printf("- %+v\n", event)
	}

	fmt.Printf("\nDetected Anomalies (%d):\n", len(eventRepo.anomalies))
	for _, anomaly := range eventRepo.anomalies {
		fmt.Printf("- %+v\n", anomaly)
	}

}

// 8. Add necessary struct definitions for in-memory repositories and enricher

// InMemoryEventRepository implements repository.EventRepository using maps
type InMemoryEventRepository struct {
	events    []*entity.SecurityEvent
	anomalies []*entity.SecurityAnalysis
	mu        sync.Mutex
}

func NewInMemoryEventRepository() *InMemoryEventRepository {
	return &InMemoryEventRepository{
		events:    make([]*entity.SecurityEvent, 0),
		anomalies: make([]*entity.SecurityAnalysis, 0),
	}
}

func (r *InMemoryEventRepository) SaveEvent(ctx context.Context, event *entity.SecurityEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	if err != nil {
		return fmt.Errorf("failed to marshal event for saving: %w", err)
	}

	// In a real application, you would store this in a database like Elasticsearch
	return nil
}

func (r *InMemoryEventRepository) SaveAnomaly(ctx context.Context, anomaly *entity.SecurityAnalysis) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.anomalies = append(r.anomalies, anomaly)
	// In a real application, you would store this in a database
	return nil
}

func (r *InMemoryEventRepository) GetEvent(ctx context.Context, id string) (*entity.SecurityEvent, error) {
	// This simple implementation doesn't support retrieval by ID
	return nil, fmt.Errorf("GetEvent not implemented for InMemoryEventRepository")
}

// InMemoryCacheRepository implements repository.CacheRepository using a map
type InMemoryCacheRepository struct {
	cache map[string]interface{}
	mu    sync.Mutex
}

func NewInMemoryCacheRepository() *InMemoryCacheRepository {
	return &InMemoryCacheRepository{
		cache: make(map[string]interface{}),
	}
}

func (r *InMemoryCacheRepository) Get(ctx context.Context, key string) (interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.cache[key]
	if !ok {
		return nil, fmt.Errorf("key not found in cache")
	}
	return value, nil
}

func (r *InMemoryCacheRepository) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = value
	// In a real application, you would handle expiration
	return nil
}

// InMemoryLogEnricher implements log.LogEnricher (assuming an interface exists)
type InMemoryLogEnricher struct {
}

func NewInMemoryLogEnricher() *InMemoryLogEnricher {
	return &InMemoryLogEnricher{}
}

func (e *InMemoryLogEnricher) Enrich(ctx context.Context, event *entity.SecurityEvent) error {
	// Simple enrichment: add a dummy field
	event.EnrichedData = map[string]interface{}{
		"enrich_status": "simulated_enrichment_successful",
	}
	return nil
}
