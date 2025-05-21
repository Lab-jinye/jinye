package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jinye/securityai/internal/service/alert"
)

// AlertHandler 处理告警相关的HTTP请求
type AlertHandler struct {
	alertManager *alert.AlertManager
}

// NewAlertHandler 创建新的告警处理器
func NewAlertHandler(manager *alert.AlertManager) *AlertHandler {
	return &AlertHandler{
		alertManager: manager,
	}
}

// RegisterRoutes 注册告警相关路由
func (h *AlertHandler) RegisterRoutes(r *gin.Engine) {
	alerts := r.Group("/api/v1/alerts")
	{
		alerts.GET("/", h.ListAlerts)
		alerts.GET("/:id", h.GetAlert)
		alerts.PUT("/:id/status", h.UpdateAlertStatus)
		alerts.POST("/:id/assign", h.AssignAlert)
		alerts.POST("/:id/resolve", h.ResolveAlert)
	}
}

// ListAlerts 获取告警列表
func (h *AlertHandler) ListAlerts(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")

	// TODO: 实现告警查询逻辑

	c.JSON(http.StatusOK, gin.H{
		"alerts": []interface{}{},
		"total":  0,
	})
}

// GetAlert 获取单个告警详情
func (h *AlertHandler) GetAlert(c *gin.Context) {
	id := c.Param("id")

	// TODO: 实现告警查询逻辑

	c.JSON(http.StatusOK, gin.H{
		"alert": nil,
	})
}

// UpdateAlertStatus 更新告警状态
func (h *AlertHandler) UpdateAlertStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: 实现状态更新逻辑

	c.JSON(http.StatusOK, gin.H{"message": "状态已更新"})
}

// AssignAlert 分配告警
func (h *AlertHandler) AssignAlert(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		AssignTo string `json:"assign_to" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: 实现分配逻辑

	c.JSON(http.StatusOK, gin.H{"message": "告警已分配"})
}

// ResolveAlert 解决告警
func (h *AlertHandler) ResolveAlert(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Resolution string `json:"resolution" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: 实现告警解决逻辑

	c.JSON(http.StatusOK, gin.H{"message": "告警已解决"})
}
