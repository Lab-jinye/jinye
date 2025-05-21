package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinye/securityai/internal/domain/repository"
	"github.com/jinye/securityai/internal/service/log"
)

// SecurityHandler handles security-related HTTP requests
type SecurityHandler struct {
	logProcessor *log.LogProcessor
	repository   repository.EventRepository
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler(
	processor *log.LogProcessor,
	repository repository.EventRepository,
) *SecurityHandler {
	return &SecurityHandler{
		logProcessor: processor,
		repository:   repository,
	}
}

// RegisterRoutes registers all the handler routes
func (h *SecurityHandler) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")
	{
		// Log processing endpoints
		api.POST("/logs", h.ProcessLogs)
		api.POST("/logs/batch", h.BatchProcessLogs)

		// Event query endpoints
		api.GET("/events/:id", h.GetEvent)
		api.GET("/events", h.ListEvents)

		// Anomaly endpoints
		api.GET("/anomalies", h.ListAnomalies)
		api.GET("/anomalies/:id", h.GetAnomaly)

		// Statistics endpoints
		api.GET("/stats/overview", h.GetOverviewStats)
		api.GET("/stats/trends", h.GetTrends)
	}
}

// ProcessLogs handles single log processing requests
func (h *SecurityHandler) ProcessLogs(c *gin.Context) {
	var request struct {
		Log string `json:"log" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format: " + err.Error(),
		})
		return
	}

	if err := h.logProcessor.ProcessLog(c, request.Log); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process log: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Log processed successfully",
	})
}

// BatchProcessLogs handles batch log processing requests
func (h *SecurityHandler) BatchProcessLogs(c *gin.Context) {
	var request struct {
		Logs []string `json:"logs" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format: " + err.Error(),
		})
		return
	}

	if err := h.logProcessor.BatchProcessLogs(c, request.Logs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logs processed successfully",
	})
}

// GetEvent retrieves a single security event
func (h *SecurityHandler) GetEvent(c *gin.Context) {
	id := c.Param("id")
	event, err := h.repository.FindEventByID(c, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Event not found",
		})
		return
	}

	c.JSON(http.StatusOK, event)
}

// ListEvents lists security events with filtering
func (h *SecurityHandler) ListEvents(c *gin.Context) {
	// Parse time range parameters
	startStr := c.Query("start")
	endStr := c.Query("end")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid start time format",
			})
			return
		}
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid end time format",
			})
			return
		}
	}

	events, err := h.repository.FindEventsByTimeRange(c, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve events",
		})
		return
	}

	c.JSON(http.StatusOK, events)
}

// ListAnomalies lists detected anomalies
func (h *SecurityHandler) ListAnomalies(c *gin.Context) {
	eventID := c.Query("event_id")

	anomalies, err := h.repository.FindAnomaliesByEventID(c, eventID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve anomalies",
		})
		return
	}

	c.JSON(http.StatusOK, anomalies)
}

// GetAnomaly retrieves a single anomaly
func (h *SecurityHandler) GetAnomaly(c *gin.Context) {
	// TODO: Implement anomaly retrieval
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented",
	})
}

// GetOverviewStats retrieves overview statistics
func (h *SecurityHandler) GetOverviewStats(c *gin.Context) {
	// TODO: Implement statistics retrieval
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented",
	})
}

// GetTrends retrieves trend analysis
func (h *SecurityHandler) GetTrends(c *gin.Context) {
	// TODO: Implement trend analysis
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "Not implemented",
	})
}
