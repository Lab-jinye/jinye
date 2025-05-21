package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/jinye/securityai/internal/domain/repository"
)

// RuleStore Elasticsearch实现的规则存储
type RuleStore struct {
	client      *elasticsearch.Client
	indexPrefix string
}

// NewRuleStore 创建规则存储实例
func NewRuleStore(client *elasticsearch.Client, indexPrefix string) *RuleStore {
	return &RuleStore{
		client:      client,
		indexPrefix: indexPrefix,
	}
}

// SaveRule 保存规则
func (s *RuleStore) SaveRule(ctx context.Context, rule *repository.RuleDefinition) error {
	// 如果是新规则，设置初始版本
	if rule.Version == 0 {
		rule.Version = 1
	} else {
		// 保存旧版本
		oldRule, err := s.GetRule(ctx, rule.ID)
		if err == nil {
			version := repository.RuleVersion{
				RuleID:    rule.ID,
				Version:   oldRule.Version,
				CreatedAt: oldRule.UpdatedAt,
				CreatedBy: oldRule.UpdatedBy,
			}
			if err := s.saveVersion(ctx, &version); err != nil {
				return err
			}
			rule.Version = oldRule.Version + 1
		}
	}

	rule.UpdatedAt = time.Now()

	body, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	_, err = s.client.Index(
		fmt.Sprintf("%srules", s.indexPrefix),
		bytes.NewReader(body),
		s.client.Index.WithDocumentID(rule.ID),
		s.client.Index.WithContext(ctx),
	)
	return err
}

// GetRule 获取规则
func (s *RuleStore) GetRule(ctx context.Context, ruleID string) (*repository.RuleDefinition, error) {
	res, err := s.client.Get(
		fmt.Sprintf("%srules", s.indexPrefix),
		ruleID,
		s.client.Get.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var rule repository.RuleDefinition
	if err := json.NewDecoder(res.Body).Decode(&rule); err != nil {
		return nil, err
	}

	return &rule, nil
}

// ListRules 获取规则列表
func (s *RuleStore) ListRules(ctx context.Context, filter repository.RuleFilter) ([]*repository.RuleDefinition, error) {
	query := buildRuleQuery(filter)

	res, err := s.client.Search(
		s.client.Search.WithIndex(fmt.Sprintf("%srules", s.indexPrefix)),
		s.client.Search.WithBody(strings.NewReader(query)),
		s.client.Search.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				Source repository.RuleDefinition `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	rules := make([]*repository.RuleDefinition, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		rules[i] = &hit.Source
	}

	return rules, nil
}

// GetRuleVersion 获取特定版本的规则
func (s *RuleStore) GetRuleVersion(ctx context.Context, ruleID string, version int) (*repository.RuleDefinition, error) {
	query := fmt.Sprintf(`{
        "query": {
            "bool": {
                "must": [
                    { "term": { "rule_id": "%s" } },
                    { "term": { "version": %d } }
                ]
            }
        }
    }`, ruleID, version)

	res, err := s.client.Search(
		s.client.Search.WithIndex(fmt.Sprintf("%srule_versions", s.indexPrefix)),
		s.client.Search.WithBody(strings.NewReader(query)),
		s.client.Search.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				Source repository.RuleDefinition `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Hits.Hits) == 0 {
		return nil, fmt.Errorf("rule version not found")
	}

	return &result.Hits.Hits[0].Source, nil
}

// 构建规则查询
func buildRuleQuery(filter repository.RuleFilter) string {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": make([]map[string]interface{}, 0),
			},
		},
	}

	must := query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{})

	if filter.Category != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"category": filter.Category,
			},
		})
	}

	if filter.Severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"severity": filter.Severity,
			},
		})
	}

	if filter.Status != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"status": filter.Status,
			},
		})
	}

	if len(filter.Tags) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{
				"tags": filter.Tags,
			},
		})
	}

	if !filter.DateFrom.IsZero() || !filter.DateTo.IsZero() {
		rangeQuery := map[string]interface{}{}
		if !filter.DateFrom.IsZero() {
			rangeQuery["gte"] = filter.DateFrom.Format(time.RFC3339)
		}
		if !filter.DateTo.IsZero() {
			rangeQuery["lte"] = filter.DateTo.Format(time.RFC3339)
		}
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{
				"created_at": rangeQuery,
			},
		})
	}

	queryBytes, _ := json.Marshal(query)
	return string(queryBytes)
}
