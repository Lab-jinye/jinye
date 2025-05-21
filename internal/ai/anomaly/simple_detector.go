package anomaly

import (
	"context"
	"fmt"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
)

// AnomalyDetector defines the interface for anomaly detection
// Assuming this interface is defined elsewhere, e.g., in an interfaces.go file
// type AnomalyDetector interface {
// 	ProcessEvents(ctx context.Context, events []*entity.SecurityEvent) ([]*entity.SecurityAnalysis, error)
// }

// SimpleAnomalyDetector implements a basic anomaly detection logic
type SimpleAnomalyDetector struct {
	// Configuration or state can be added here if needed
}

// NewSimpleAnomalyDetector creates a new SimpleAnomalyDetector instance
func NewSimpleAnomalyDetector() *SimpleAnomalyDetector {
	return &SimpleAnomalyDetector{}
}

// ProcessEvents processes a batch of security events to detect simple anomalies
func (d *SimpleAnomalyDetector) ProcessEvents(ctx context.Context, events []*entity.SecurityEvent) ([]*entity.SecurityAnalysis, error) {
	anomalies := []*entity.SecurityAnalysis{}
	ipCounts := make(map[string]int)

	// Count occurrences of source IPs
	for _, event := range events {
		ipCounts[event.SourceIP]++
	}

	// Check for source IPs with high counts
	for ip, count := range ipCounts {
		if count > 10 { // Simple threshold: more than 10 events from the same source IP in the batch
			// Create an anomaly analysis entry
			anomaly := entity.NewSecurityAnalysis()
			anomaly.Timestamp = time.Now() // Use current time for analysis time
			anomaly.EventType = "SimpleAnomalyDetection"
			anomaly.Description = fmt.Sprintf("Potential anomaly: Source IP %s appeared %d times in the batch.", ip, count)
			anomaly.Severity = "Medium" // Assign a severity level
			anomaly.Source = "SimpleAnomalyDetector"

			// Find one of the events related to this IP to link the analysis
			for _, event := range events {
				if event.SourceIP == ip {
					anomaly.EventID = event.ID // Assuming SecurityEvent has an ID field
					break
				}
			}

			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies, nil
}