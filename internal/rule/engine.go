package rule

import (
	"context"
	"sync"

	"github.com/jinye/securityai/internal/domain/entity"
)

// Engine 规则引擎
type Engine struct {
	rules   map[string]Rule
	mutex   sync.RWMutex
	metrics *RuleMetrics
}

// RuleMetrics 规则执行指标
type RuleMetrics struct {
	TotalExecutions   int64
	MatchedExecutions int64
	ExecutionTimes    []float64
	RuleMatchCounts   map[string]int64
}

// NewEngine 创建新的规则引擎
func NewEngine() *Engine {
	return &Engine{
		rules: make(map[string]Rule),
		metrics: &RuleMetrics{
			RuleMatchCounts: make(map[string]int64),
		},
	}
}

// AddRule 添加规则到引擎
func (e *Engine) AddRule(rule Rule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	metadata := rule.GetMetadata()
	e.rules[metadata.ID] = rule
}

// RemoveRule 从引擎中移除规则
func (e *Engine) RemoveRule(ruleID string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	delete(e.rules, ruleID)
}

// EvaluateEvent 评估事件是否匹配规则
func (e *Engine) EvaluateEvent(ctx context.Context, event *entity.SecurityEvent) []RuleResult {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	results := make([]RuleResult, 0)

	for _, rule := range e.rules {
		metadata := rule.GetMetadata()

		// 评估规则
		matched := rule.Evaluate(ctx, event)

		// 更新指标
		e.metrics.TotalExecutions++
		if matched {
			e.metrics.MatchedExecutions++
			e.metrics.RuleMatchCounts[metadata.ID]++
		}

		// 如果规则匹配，添加到结果中
		if matched {
			results = append(results, RuleResult{
				RuleID:   metadata.ID,
				RuleName: metadata.Name,
				Severity: metadata.Severity,
				Category: metadata.Category,
				Matched:  true,
			})
		}
	}

	return results
}

// RuleResult 规则评估结果
type RuleResult struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Matched  bool   `json:"matched"`
}

// GetMetrics 获取规则执行指标
func (e *Engine) GetMetrics() *RuleMetrics {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return &RuleMetrics{
		TotalExecutions:   e.metrics.TotalExecutions,
		MatchedExecutions: e.metrics.MatchedExecutions,
		RuleMatchCounts:   e.metrics.RuleMatchCounts,
	}
}

// LoadRuleFromJSON 从JSON配置加载规则
func (e *Engine) LoadRuleFromJSON(jsonConfig string) error {
	// TODO: 实现从JSON配置加载规则的逻辑
	return nil
}

// GetRuleByID 获取指定ID的规则
func (e *Engine) GetRuleByID(ruleID string) (Rule, bool) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	rule, exists := e.rules[ruleID]
	return rule, exists
}
