package anomaly

import (
	"context"
	"math"

	"github.com/bytedance/eino"
	"github.com/bytedance/eino/model"
	"github.com/jinye/securityai/internal/domain/entity"
	"github.com/jinye/securityai/internal/domain/repository"
)

// AnomalyDetector represents the anomaly detection engine
type AnomalyDetector struct {
	engine     *eino.Engine
	model      model.Model
	repository repository.EventRepository
	vectorRepo repository.VectorRepository
	threshold  float32
	batchSize  int
}

// NewAnomalyDetector creates a new instance of the anomaly detector
func NewAnomalyDetector(
	engine *eino.Engine,
	modelPath string,
	repository repository.EventRepository,
	vectorRepo repository.VectorRepository,
	threshold float32,
	batchSize int,
) (*AnomalyDetector, error) {
	// Load the anomaly detection model
	model, err := engine.LoadModel(modelPath)
	if err != nil {
		return nil, err
	}

	return &AnomalyDetector{
		engine:     engine,
		model:      model,
		repository: repository,
		vectorRepo: vectorRepo,
		threshold:  threshold,
		batchSize:  batchSize,
	}, nil
}

// ProcessEvents processes a batch of security events for anomaly detection
func (d *AnomalyDetector) ProcessEvents(ctx context.Context, events []*entity.SecurityEvent) ([]*entity.AnomalyResult, error) {
	batch := make([]map[string]interface{}, 0, len(events))

	// Prepare batch data
	for _, event := range events {
		input := map[string]interface{}{
			"timestamp": event.Timestamp.Unix(),
			"source_ip": event.SourceIP,
			"dest_ip":   event.DestIP,
			"protocol":  event.Protocol,
			"port":      event.Port,
			"action":    event.Action,
			"status":    event.Status,
			"user":      event.User,
		}
		batch = append(batch, input)
	}

	// Perform batch prediction
	results, err := d.model.BatchPredict(ctx, batch)
	if err != nil {
		return nil, err
	}

	// Process results
	anomalies := make([]*entity.AnomalyResult, 0)
	for i, result := range results {
		score, ok := result["anomaly_score"].(float32)
		if !ok {
			continue
		}

		if score > d.threshold {
			anomaly := entity.NewAnomalyResult(events[i].ID, score)
			anomaly.AnomalyType = d.determineAnomalyType(result)
			anomaly.Confidence = d.calculateConfidence(score, d.threshold)
			anomaly.Rules = d.findRelatedRules(events[i], score)

			anomalies = append(anomalies, anomaly)

			// Save anomaly result
			if err := d.repository.SaveAnomaly(ctx, anomaly); err != nil {
				return nil, err
			}
		}

		// Save event vector if available
		if vector, ok := result["event_vector"].([]float32); ok {
			if err := d.vectorRepo.SaveEventVector(ctx, events[i].ID, vector); err != nil {
				return nil, err
			}
		}
	}

	return anomalies, nil
}

// determineAnomalyType determines the type of anomaly based on the model output
func (d *AnomalyDetector) determineAnomalyType(result map[string]interface{}) string {
	score, ok := result["anomaly_score"].(float32)
	if !ok {
		return "unknown"
	}

	switch {
	case score > 0.9:
		return "critical"
	case score > 0.7:
		return "high"
	case score > 0.5:
		return "medium"
	default:
		return "low"
	}
}

// calculateConfidence calculates the confidence score
func (d *AnomalyDetector) calculateConfidence(score, threshold float32) float32 {
	diff := score - threshold
	return 1.0 / (1.0 + float32(math.Exp(float64(-diff*10))))
}

// findRelatedRules finds security rules related to the detected anomaly
func (d *AnomalyDetector) findRelatedRules(event *entity.SecurityEvent, score float32) []string {
	// TODO: Implement rule matching logic
	return []string{}
}
