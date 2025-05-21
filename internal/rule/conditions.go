package rule

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/jinye/securityai/internal/domain/entity"
)

// FieldCondition 字段条件
type FieldCondition struct {
	Field    string      // 字段名
	Operator string      // 操作符: eq, neq, gt, lt, contains, regex
	Value    interface{} // 比较值
}

func NewFieldCondition(field, operator string, value interface{}) *FieldCondition {
	return &FieldCondition{
		Field:    field,
		Operator: operator,
		Value:    value,
	}
}

func (c *FieldCondition) Evaluate(event *entity.SecurityEvent) bool {
	fieldValue := getFieldValue(event, c.Field)

	switch c.Operator {
	case "eq":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", c.Value)
	case "neq":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", c.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", c.Value))
	case "regex":
		pattern, ok := c.Value.(string)
		if !ok {
			return false
		}
		matched, err := regexp.MatchString(pattern, fmt.Sprintf("%v", fieldValue))
		return err == nil && matched
	}

	return false
}

// IPCondition IP地址相关条件
type IPCondition struct {
	Field    string   // IP字段名
	Networks []string // CIDR格式的网络地址
}

func NewIPCondition(field string, networks []string) *IPCondition {
	return &IPCondition{
		Field:    field,
		Networks: networks,
	}
}

func (c *IPCondition) Evaluate(event *entity.SecurityEvent) bool {
	ipStr := getFieldValue(event, c.Field).(string)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, network := range c.Networks {
		_, subnet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// LabelCondition 标签条件
type LabelCondition struct {
	Labels   []string // 需要匹配的标签
	MatchAll bool     // 是否需要匹配所有标签
}

func NewLabelCondition(labels []string, matchAll bool) *LabelCondition {
	return &LabelCondition{
		Labels:   labels,
		MatchAll: matchAll,
	}
}

func (c *LabelCondition) Evaluate(event *entity.SecurityEvent) bool {
	if c.MatchAll {
		for _, label := range c.Labels {
			found := false
			for _, eventLabel := range event.Labels {
				if eventLabel == label {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	// 匹配任意标签
	for _, label := range c.Labels {
		for _, eventLabel := range event.Labels {
			if eventLabel == label {
				return true
			}
		}
	}
	return false
}

// TimeWindowCondition 时间窗口条件
type TimeWindowCondition struct {
	StartHour int
	EndHour   int
}

func NewTimeWindowCondition(startHour, endHour int) *TimeWindowCondition {
	return &TimeWindowCondition{
		StartHour: startHour,
		EndHour:   endHour,
	}
}

func (c *TimeWindowCondition) Evaluate(event *entity.SecurityEvent) bool {
	hour := event.Timestamp.Hour()
	if c.StartHour <= c.EndHour {
		return hour >= c.StartHour && hour <= c.EndHour
	}
	// 处理跨天的情况
	return hour >= c.StartHour || hour <= c.EndHour
}

// 辅助函数：获取事件中指定字段的值
func getFieldValue(event *entity.SecurityEvent, field string) interface{} {
	switch field {
	case "source_ip":
		return event.SourceIP
	case "dest_ip":
		return event.DestIP
	case "protocol":
		return event.Protocol
	case "port":
		return event.Port
	case "action":
		return event.Action
	case "status":
		return event.Status
	case "user":
		return event.User
	case "severity":
		return event.Severity
	default:
		return nil
	}
}
