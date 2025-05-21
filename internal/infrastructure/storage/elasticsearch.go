package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/jinye/securityai/internal/domain/entity"
)

type ElasticsearchRepository struct {
	client      *elasticsearch.Client
	indexPrefix string
}

func NewElasticsearchRepository(config elasticsearch.Config, indexPrefix string) (*ElasticsearchRepository, error) {
	client, err := elasticsearch.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &ElasticsearchRepository{
		client:      client,
		indexPrefix: indexPrefix,
	}, nil
}

func (r *ElasticsearchRepository) SaveEvent(ctx context.Context, event *entity.SecurityEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = r.client.Index(
		r.indexPrefix+"events",
		bytes.NewReader(body),
		r.client.Index.WithDocumentID(event.ID),
		r.client.Index.WithContext(ctx),
	)
	return err
}

func (r *ElasticsearchRepository) FindEventByID(ctx context.Context, id string) (*entity.SecurityEvent, error) {
	res, err := r.client.Get(
		r.indexPrefix+"events",
		id,
		r.client.Get.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var event entity.SecurityEvent
	if err := json.NewDecoder(res.Body).Decode(&event); err != nil {
		return nil, err
	}

	return &event, nil
}

func (r *ElasticsearchRepository) FindEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*entity.SecurityEvent, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	res, err := r.client.Search(
		r.client.Search.WithIndex(r.indexPrefix+"events"),
		r.client.Search.WithBody(bytes.NewReader(body)),
		r.client.Search.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				Source entity.SecurityEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	events := make([]*entity.SecurityEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = &hit.Source
	}

	return events, nil
}

func (r *ElasticsearchRepository) SaveAnomaly(ctx context.Context, anomaly *entity.AnomalyResult) error {
	body, err := json.Marshal(anomaly)
	if err != nil {
		return err
	}

	_, err = r.client.Index(
		r.indexPrefix+"anomalies",
		bytes.NewReader(body),
		r.client.Index.WithDocumentID(anomaly.ID),
		r.client.Index.WithContext(ctx),
	)
	return err
}

func (r *ElasticsearchRepository) FindAnomaliesByEventID(ctx context.Context, eventID string) ([]*entity.AnomalyResult, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"event_id": eventID,
			},
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	res, err := r.client.Search(
		r.client.Search.WithIndex(r.indexPrefix+"anomalies"),
		r.client.Search.WithBody(bytes.NewReader(body)),
		r.client.Search.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				Source entity.AnomalyResult `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	anomalies := make([]*entity.AnomalyResult, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		anomalies[i] = &hit.Source
	}

	return anomalies, nil
}
