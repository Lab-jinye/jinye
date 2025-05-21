package repository

import (
	"context"
	"time"
)

// RuleStore 定义规则存储接口
type RuleStore interface {
	// SaveRule 保存规则
	SaveRule(ctx context.Context, rule *RuleDefinition) error

	// GetRule 获取规则
	GetRule(ctx context.Context, ruleID string) (*RuleDefinition, error)

	// ListRules 获取规则列表
	ListRules(ctx context.Context, filter RuleFilter) ([]*RuleDefinition, error)

	// DeleteRule 删除规则
	DeleteRule(ctx context.Context, ruleID string) error

	// GetRuleVersion 获取特定版本的规则
	GetRuleVersion(ctx context.Context, ruleID string, version int) (*RuleDefinition, error)

	// ListRuleVersions 获取规则的所有版本
	ListRuleVersions(ctx context.Context, ruleID string) ([]*RuleVersion, error)
}

// RuleDefinition 规则定义
type RuleDefinition struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Version     int                    `json:"version"`
	Status      string                 `json:"status"` // active, inactive, deprecated
	Config      RuleConfig             `json:"config"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	UpdatedBy   string                 `json:"updated_by"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RuleConfig 规则配置
type RuleConfig struct {
	Type       string                   `json:"type"` // composite, ml, simple
	Conditions []map[string]interface{} `json:"conditions"`
	Operator   string                   `json:"operator,omitempty"` // AND, OR
	Threshold  float32                  `json:"threshold,omitempty"`
	Actions    []RuleAction             `json:"actions"`
}

// RuleAction 规则触发的动作
type RuleAction struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// RuleVersion 规则版本信息
type RuleVersion struct {
	RuleID    string    `json:"rule_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	ChangeLog string    `json:"change_log"`
}

// RuleFilter 规则查询过滤条件
type RuleFilter struct {
	Category string    `json:"category,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Status   string    `json:"status,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	DateFrom time.Time `json:"date_from,omitempty"`
	DateTo   time.Time `json:"date_to,omitempty"`
}
