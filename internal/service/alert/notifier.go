package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// WebhookNotifier 实现基于Webhook的告警通知
type WebhookNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewWebhookNotifier 创建新的Webhook通知器
func NewWebhookNotifier(webhookURL string) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{},
	}
}

// Send 通过Webhook发送告警
func (n *WebhookNotifier) Send(ctx context.Context, alert *Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// EmailNotifier 实现基于邮件的告警通知
type EmailNotifier struct {
	smtpServer string
	smtpPort   int
	username   string
	password   string
	from       string
	to         []string
}

// NewEmailNotifier 创建新的邮件通知器
func NewEmailNotifier(server string, port int, username, password string, from string, to []string) *EmailNotifier {
	return &EmailNotifier{
		smtpServer: server,
		smtpPort:   port,
		username:   username,
		password:   password,
		from:       from,
		to:         to,
	}
}

// Send 通过邮件发送告警
func (n *EmailNotifier) Send(ctx context.Context, alert *Alert) error {
	// TODO: 实现邮件发送逻辑
	return nil
}

// DingTalkNotifier 实现钉钉机器人告警通知
type DingTalkNotifier struct {
	webhookToken string
}

// NewDingTalkNotifier 创建新的钉钉通知器
func NewDingTalkNotifier(token string) *DingTalkNotifier {
	return &DingTalkNotifier{
		webhookToken: token,
	}
}

// Send 通过钉钉发送告警
func (n *DingTalkNotifier) Send(ctx context.Context, alert *Alert) error {
	message := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "安全告警: " + alert.Title,
			"text": fmt.Sprintf("### %s\n\n"+
				"**严重程度**: %s\n\n"+
				"**描述**: %s\n\n"+
				"**时间**: %s\n\n"+
				"**事件ID**: %s\n\n",
				alert.Title,
				alert.Severity,
				alert.Description,
				alert.CreatedAt.Format("2006-01-02 15:04:05"),
				alert.EventID),
		},
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}

	url := "https://oapi.dingtalk.com/robot/send?access_token=" + n.webhookToken
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
