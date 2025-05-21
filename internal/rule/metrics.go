package rule

import (
	"sort"
	"sync"
	"time"
)

// RuleMetrics 规则执行指标收集器
type RuleMetrics struct {
	mutex sync.RWMutex

	// 规则执行统计
	ruleExecutions    map[string]int64           // 规则执行次数
	ruleMatches       map[string]int64           // 规则匹配次数
	ruleExecutionTime map[string][]time.Duration // 规则执行时间

	// 每日统计
	dailyMatches map[string]map[string]int64 // 按日期统计的规则匹配次数

	// 性能指标
	slowestRules     map[string]time.Duration // 最慢的规则执行时间
	topMatchingRules map[string]int64         // 匹配次数最多的规则
}

// NewRuleMetrics 创建新的规则指标收集器
func NewRuleMetrics() *RuleMetrics {
	return &RuleMetrics{
		ruleExecutions:    make(map[string]int64),
		ruleMatches:       make(map[string]int64),
		ruleExecutionTime: make(map[string][]time.Duration),
		dailyMatches:      make(map[string]map[string]int64),
		slowestRules:      make(map[string]time.Duration),
		topMatchingRules:  make(map[string]int64),
	}
}

// TrackRuleExecution 记录规则执行
func (m *RuleMetrics) TrackRuleExecution(ruleID string, duration time.Duration, matched bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 更新执行次数
	m.ruleExecutions[ruleID]++

	// 更新匹配次数
	if matched {
		m.ruleMatches[ruleID]++
	}

	// 更新执行时间
	m.ruleExecutionTime[ruleID] = append(m.ruleExecutionTime[ruleID], duration)

	// 更新每日统计
	date := time.Now().Format("2006-01-02")
	if m.dailyMatches[date] == nil {
		m.dailyMatches[date] = make(map[string]int64)
	}
	if matched {
		m.dailyMatches[date][ruleID]++
	}

	// 更新最慢规则统计
	if currentSlowest, exists := m.slowestRules[ruleID]; !exists || duration > currentSlowest {
		m.slowestRules[ruleID] = duration
	}

	// 更新最常匹配规则统计
	if matched {
		m.topMatchingRules[ruleID]++
	}
}

// GetRuleStats 获取规则统计信息
func (m *RuleMetrics) GetRuleStats(ruleID string) map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := make(map[string]interface{})

	// 基本统计
	stats["total_executions"] = m.ruleExecutions[ruleID]
	stats["total_matches"] = m.ruleMatches[ruleID]

	// 计算平均执行时间
	var totalTime time.Duration
	execTimes := m.ruleExecutionTime[ruleID]
	for _, t := range execTimes {
		totalTime += t
	}
	if len(execTimes) > 0 {
		stats["avg_execution_time_ms"] = float64(totalTime) / float64(len(execTimes)) / float64(time.Millisecond)
	}

	// 匹配率
	if m.ruleExecutions[ruleID] > 0 {
		stats["match_rate"] = float64(m.ruleMatches[ruleID]) / float64(m.ruleExecutions[ruleID])
	}

	return stats
}

// GetTopMatchingRules 获取匹配次数最多的规则
func (m *RuleMetrics) GetTopMatchingRules(limit int) []map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	type ruleMatch struct {
		ID      string
		Matches int64
	}

	// 将map转换为切片以便排序
	rules := make([]ruleMatch, 0, len(m.topMatchingRules))
	for id, matches := range m.topMatchingRules {
		rules = append(rules, ruleMatch{id, matches})
	}

	// 按匹配次数排序
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Matches > rules[j].Matches
	})

	// 限制返回数量
	if limit > len(rules) {
		limit = len(rules)
	}

	// 构造结果
	result := make([]map[string]interface{}, limit)
	for i := 0; i < limit; i++ {
		result[i] = map[string]interface{}{
			"rule_id": rules[i].ID,
			"matches": rules[i].Matches,
		}
	}

	return result
}

// GetSlowestRules 获取执行最慢的规则
func (m *RuleMetrics) GetSlowestRules(limit int) []map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	type ruleDuration struct {
		ID       string
		Duration time.Duration
	}

	// 将map转换为切片以便排序
	rules := make([]ruleDuration, 0, len(m.slowestRules))
	for id, duration := range m.slowestRules {
		rules = append(rules, ruleDuration{id, duration})
	}

	// 按执行时间排序
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Duration > rules[j].Duration
	})

	// 限制返回数量
	if limit > len(rules) {
		limit = len(rules)
	}

	// 构造结果
	result := make([]map[string]interface{}, limit)
	for i := 0; i < limit; i++ {
		result[i] = map[string]interface{}{
			"rule_id":           rules[i].ID,
			"execution_time_ms": float64(rules[i].Duration) / float64(time.Millisecond),
		}
	}

	return result
}

// GetDailyStats 获取每日统计信息
func (m *RuleMetrics) GetDailyStats(days int) map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := make(map[string]interface{})

	// 获取最近n天的数据
	now := time.Now()
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		if matches, exists := m.dailyMatches[date]; exists {
			stats[date] = matches
		}
	}

	return stats
}
