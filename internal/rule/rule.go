package rule

import (
	"context"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
)

// Rule 定义安全规则接口
type Rule interface {
	// Evaluate 评估规则是否匹配
	Evaluate(ctx context.Context, event *entity.SecurityEvent) bool
	// GetMetadata 获取规则元数据
	GetMetadata() RuleMetadata
}

// RuleMetadata 规则元数据
type RuleMetadata struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Version     string    `json:"version"`
	Author      string    `json:"author"`
}

// Condition 规则条件接口
type Condition interface {
	Evaluate(event *entity.SecurityEvent) bool
}

// CompositeRule 组合规则
type CompositeRule struct {
	metadata   RuleMetadata
	conditions []Condition
	operator   string // "AND" or "OR"
}

func NewCompositeRule(metadata RuleMetadata, operator string) *CompositeRule {
	return &CompositeRule{
		metadata:   metadata,
		conditions: make([]Condition, 0),
		operator:   operator,
	}
}

func (r *CompositeRule) AddCondition(condition Condition) {
	r.conditions = append(r.conditions, condition)
}

func (r *CompositeRule) Evaluate(ctx context.Context, event *entity.SecurityEvent) bool {
	if len(r.conditions) == 0 {
		return false
	}

	if r.operator == "AND" {
		for _, condition := range r.conditions {
			if !condition.Evaluate(event) {
				return false
			}
		}
		return true
	}

	// OR operator
	for _, condition := range r.conditions {
		if condition.Evaluate(event) {
			return true
		}
	}
	return false
}

func (r *CompositeRule) GetMetadata() RuleMetadata {
	return r.metadata
}

// MLBasedRule 基于机器学习的规则
type MLBasedRule struct {
	metadata  RuleMetadata
	model     MLModel
	threshold float32
}

// MLModel 机器学习模型接口
type MLModel interface {
	Predict(ctx context.Context, event *entity.SecurityEvent) (float32, error)
}

func NewMLBasedRule(metadata RuleMetadata, model MLModel, threshold float32) *MLBasedRule {
	return &MLBasedRule{
		metadata:  metadata,
		model:     model,
		threshold: threshold,
	}
}

func (r *MLBasedRule) Evaluate(ctx context.Context, event *entity.SecurityEvent) bool {
	score, err := r.model.Predict(ctx, event)
	if err != nil {
		// 记录错误并返回false
		return false
	}
	return score > r.threshold
}

func (r *MLBasedRule) GetMetadata() RuleMetadata {
	return r.metadata
}
