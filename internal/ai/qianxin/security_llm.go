package qianxin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jinye/securityai/internal/domain/entity"
)

// SecurityLLM represents the QianXin security large language model client
type SecurityLLM struct {
	apiEndpoint string
	apiKey     string
	httpClient *http.Client
}

// NewSecurityLLM creates a new instance of SecurityLLM
func NewSecurityLLM(apiEndpoint, apiKey string) *SecurityLLM {
	return &SecurityLLM{
		apiEndpoint: apiEndpoint,
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

// AnalyzeSecurityEvent analyzes a security event using QianXin's security LLM
func (s *SecurityLLM) AnalyzeSecurityEvent(ctx context.Context, event *entity.SecurityEvent) (*entity.SecurityAnalysis, error) {
	// 构建模型输入
	input := map[string]interface{}{
		"event_type": "security_analysis",
		"data": map[string]interface{}{
			"timestamp": event.Timestamp,
			"source_ip": event.SourceIP,
			"dest_ip":   event.DestIP,
			"protocol":  event.Protocol,
			"port":      event.Port,
			"action":    event.Action,
			"status":    event.Status,
			"user":      event.User,
		},
	}

	// 调用安全大模型API
	response, err := s.callAPI(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to call security LLM API: %v", err)
	}

	// 解析模型响应
	analysis := &entity.SecurityAnalysis{
		EventID:        event.ID,
		ThreatLevel:    response.ThreatLevel,
		ThreatType:     response.ThreatType,
		Recommendation: response.Recommendation,
		Confidence:     response.Confidence,
	}

	return analysis, nil
}

// DetectAnomalies detects anomalies in security events using QianXin's security LLM
func (s *SecurityLLM) DetectAnomalies(ctx context.Context, events []*entity.SecurityEvent) ([]*entity.AnomalyResult, error) {
	// 批量分析事件
	anomalies := make([]*entity.AnomalyResult, 0)
	for _, event := range events {
		analysis, err := s.AnalyzeSecurityEvent(ctx, event)
		if err != nil {
			continue
		}

		// 根据威胁等级判断是否为异常
		if analysis.ThreatLevel >= "medium" {
			anomaly := entity.NewAnomalyResult(event.ID, float32(analysis.Confidence))
			anomaly.AnomalyType = analysis.ThreatType
			anomaly.Description = analysis.Recommendation
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies, nil
}

// callAPI makes an HTTP request to the QianXin security LLM API
func (s *SecurityLLM) callAPI(ctx context.Context, input interface{}) (*APIResponse, error) {
    // 构建请求体
    reqBody, err := json.Marshal(input)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request body: %v", err)
    }

    // 创建HTTP请求
    req, err := http.NewRequestWithContext(ctx, "POST", s.apiEndpoint, bytes.NewBuffer(reqBody))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }

    // 设置请求头
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiKey))

    // 发送请求
    resp, err := s.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()

    // 检查响应状态码
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
    }

    // 解析响应
    var apiResp APIResponse
    if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %v", err)
    }

    return &apiResp, nil
}

// APIResponse represents the response from QianXin's security LLM API
type APIResponse struct {
	ThreatLevel    string  `json:"threat_level"`
	ThreatType     string  `json:"threat_type"`
	Recommendation string  `json:"recommendation"`
	Confidence     float64 `json:"confidence"`
}