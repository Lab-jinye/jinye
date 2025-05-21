package alert

import (
	"context"
	"sync"
	"time"

	"github.com/jinye/securityai/internal/domain/entity"
)

// AlertManager 管理安全告警的生成和分发
type AlertManager struct {
	notifiers []Notifier
	rules     []AlertRule
	mutex     sync.RWMutex
}

// AlertRule 定义告警规则
type AlertRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Condition   func(event *entity.SecurityEvent) bool
	Throttle    time.Duration
}

// Notifier 定义告警通知接口
type Notifier interface {
	// Send 发送告警通知
	Send(ctx context.Context, alert *Alert) error
}

// Alert 表示一个安全告警
type Alert struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
	Status      string    `json:"status"`
	AssignedTo  string    `json:"assigned_to,omitempty"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
	Resolution  string    `json:"resolution,omitempty"`
}

// NewAlertManager 创建新的告警管理器
func NewAlertManager(notifiers []Notifier) *AlertManager {
	return &AlertManager{
		notifiers: notifiers,
		rules:     make([]AlertRule, 0),
	}
}

// AddRule 添加新的告警规则
func (m *AlertManager) AddRule(rule AlertRule) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.rules = append(m.rules, rule)
}

// ProcessEvent 处理安全事件并生成告警
func (m *AlertManager) ProcessEvent(ctx context.Context, event *entity.SecurityEvent) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, rule := range m.rules {
		if rule.Condition(event) {
			alert := &Alert{
				ID:          generateID(),
				EventID:     event.ID,
				RuleID:      rule.ID,
				Title:       rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				CreatedAt:   time.Now(),
				Status:      "new",
			}

			// 发送告警通知
			for _, notifier := range m.notifiers {
				if err := notifier.Send(ctx, alert); err != nil {
					// 记录错误但继续处理其他通知器
					continue
				}
			}
		}
	}

	return nil
}

// DefaultRules 返回默认的告警规则集
func DefaultRules() []AlertRule {
	return []AlertRule{
		{
			ID:          "CRIT-001",
			Name:        "严重异常行为检测",
			Description: "检测到严重级别的异常行为",
			Severity:    "critical",
			Condition: func(event *entity.SecurityEvent) bool {
				return event.Severity == "critical"
			},
			Throttle: 5 * time.Minute,
		},
		{
			ID:          "SEC-001",
			Name:        "可疑IP访问检测",
			Description: "检测到来自可疑IP地址的访问",
			Severity:    "high",
			Condition: func(event *entity.SecurityEvent) bool {
				for _, label := range event.Labels {
					if label == "source_reputation:malicious" {
						return true
					}
				}
				return false
			},
			Throttle: 15 * time.Minute,
		},
	}
}

func generateID() string {
	return time.Now().Format("20060102150405") + randString(6)
}

func randString(n int) string {
	// 实现简单的随机字符串生成
	return "123456" // TODO: 实现真实的随机字符串生成
}
