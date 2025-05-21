package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
	"github.com/jinye/securityai/internal/domain/repository"
)

// RuleManager 规则管理器
type RuleManager struct {
	store   repository.RuleStore
	engine  *Engine
	metrics *RuleMetrics
}

// NewRuleManager 创建规则管理器
func NewRuleManager(store repository.RuleStore, engine *Engine) *RuleManager {
	return &RuleManager{
		store:   store,
		engine:  engine,
		metrics: NewRuleMetrics(),
	}
}

// ImportRules 从JSON文件导入规则
func (m *RuleManager) ImportRules(ctx context.Context, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %v", err)
	}

	var rules []*repository.RuleDefinition
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("解析规则文件失败: %v", err)
	}

	for _, rule := range rules {
		if err := m.ValidateRule(rule); err != nil {
			return fmt.Errorf("规则验证失败 [%s]: %v", rule.ID, err)
		}

		if err := m.store.SaveRule(ctx, rule); err != nil {
			return fmt.Errorf("保存规则失败 [%s]: %v", rule.ID, err)
		}

		// 将规则加载到引擎中
		engineRule, err := m.ConvertToEngineRule(rule)
		if err != nil {
			return fmt.Errorf("转换规则失败 [%s]: %v", rule.ID, err)
		}

		m.engine.AddRule(engineRule)
	}

	return nil
}

// ExportRules 导出规则到JSON文件
func (m *RuleManager) ExportRules(ctx context.Context, filePath string, filter repository.RuleFilter) error {
	rules, err := m.store.ListRules(ctx, filter)
	if err != nil {
		return fmt.Errorf("获取规则列表失败: %v", err)
	}

	data, err := json.MarshalIndent(rules, "", "    ")
	if err != nil {
		return fmt.Errorf("序列化规则失败: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("写入规则文件失败: %v", err)
	}

	return nil
}

// TestRule 测试规则
func (m *RuleManager) TestRule(ctx context.Context, rule *repository.RuleDefinition, testEvents []*TestEvent) (*TestResult, error) {
	engineRule, err := m.ConvertToEngineRule(rule)
	if err != nil {
		return nil, err
	}

	result := &TestResult{
		RuleID:      rule.ID,
		StartTime:   time.Now(),
		TestResults: make([]TestEventResult, 0, len(testEvents)),
	}

	for _, event := range testEvents {
		matched := engineRule.Evaluate(ctx, event.Event)
		result.TestResults = append(result.TestResults, TestEventResult{
			EventID:     event.ID,
			Expected:    event.ExpectedResult,
			Actual:      matched,
			MatchedRule: matched,
		})
	}

	result.EndTime = time.Now()
	result.CalculateStats()

	return result, nil
}

// TestEvent 测试事件
type TestEvent struct {
	ID             string
	Event          *entity.SecurityEvent
	ExpectedResult bool
}

// TestResult 测试结果
type TestResult struct {
	RuleID      string
	StartTime   time.Time
	EndTime     time.Time
	TestResults []TestEventResult
	Stats       TestStats
}

// TestEventResult 单个测试事件的结果
type TestEventResult struct {
	EventID     string
	Expected    bool
	Actual      bool
	MatchedRule bool
}

// TestStats 测试统计
type TestStats struct {
	TotalTests    int
	TotalSuccess  int
	TotalFailure  int
	FalsePositive int
	FalseNegative int
	Accuracy      float64
	Precision     float64
	Recall        float64
}

// CalculateStats 计算测试统计信息
func (r *TestResult) CalculateStats() {
	stats := TestStats{
		TotalTests: len(r.TestResults),
	}

	for _, result := range r.TestResults {
		if result.Expected == result.Actual {
			stats.TotalSuccess++
		} else {
			stats.TotalFailure++
			if result.Actual && !result.Expected {
				stats.FalsePositive++
			} else if !result.Actual && result.Expected {
				stats.FalseNegative++
			}
		}
	}

	if stats.TotalTests > 0 {
		stats.Accuracy = float64(stats.TotalSuccess) / float64(stats.TotalTests)
	}

	truePositive := stats.TotalSuccess - stats.FalsePositive
	if truePositive+stats.FalsePositive > 0 {
		stats.Precision = float64(truePositive) / float64(truePositive+stats.FalsePositive)
	}

	if truePositive+stats.FalseNegative > 0 {
		stats.Recall = float64(truePositive) / float64(truePositive+stats.FalseNegative)
	}

	r.Stats = stats
}

// ValidateRule 验证规则定义
func (m *RuleManager) ValidateRule(rule *repository.RuleDefinition) error {
	if rule.ID == "" {
		return fmt.Errorf("规则ID不能为空")
	}
	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	// 添加更多验证逻辑...
	return nil
}

// ConvertToEngineRule 将规则定义转换为引擎规则
func (m *RuleManager) ConvertToEngineRule(def *repository.RuleDefinition) (Rule, error) {
	metadata := RuleMetadata{
		ID:          def.ID,
		Name:        def.Name,
		Description: def.Description,
		Severity:    def.Severity,
		Category:    def.Category,
		Tags:        def.Tags,
	}

	switch def.Config.Type {
	case "composite":
		rule := NewCompositeRule(metadata, def.Config.Operator)
		for _, condition := range def.Config.Conditions {
			// 转换条件配置...
			// TODO: 实现条件转换逻辑
		}
		return rule, nil
	case "ml":
		// TODO: 实现ML规则转换逻辑
		return nil, fmt.Errorf("ML规则类型暂不支持")
	default:
		return nil, fmt.Errorf("未知的规则类型: %s", def.Config.Type)
	}
}
