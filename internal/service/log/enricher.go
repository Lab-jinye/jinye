package log

import (
	"context"
	"strings"
	"sync"

	"github.com/jinye/securityai/internal/domain/entity"
)

// LogEnricher enriches security events with additional context
type LogEnricher struct {
	geoIPDB      GeoIPDatabase
	reputationDB ThreatDB
	cache        map[string]interface{}
	mutex        sync.RWMutex
}

// NewLogEnricher creates a new log enricher
func NewLogEnricher(geoIP GeoIPDatabase, threatDB ThreatDB) *LogEnricher {
	return &LogEnricher{
		geoIPDB:      geoIP,
		reputationDB: threatDB,
		cache:        make(map[string]interface{}),
	}
}

// Enrich adds additional context to a security event
func (e *LogEnricher) Enrich(ctx context.Context, event *entity.SecurityEvent) error {
	// Enrich IP information
	if event.SourceIP != "" {
		if err := e.enrichIPInfo(ctx, event, event.SourceIP, "source"); err != nil {
			return err
		}
	}

	if event.DestIP != "" {
		if err := e.enrichIPInfo(ctx, event, event.DestIP, "dest"); err != nil {
			return err
		}
	}

	// Enrich user information
	if event.User != "" {
		if err := e.enrichUserInfo(ctx, event); err != nil {
			return err
		}
	}

	// Calculate severity based on enriched data
	e.calculateSeverity(event)

	return nil
}

// enrichIPInfo adds geographical and reputation data for an IP
func (e *LogEnricher) enrichIPInfo(ctx context.Context, event *entity.SecurityEvent, ip string, direction string) error {
	// Check cache first
	cacheKey := "ip:" + ip
	e.mutex.RLock()
	if cached, ok := e.cache[cacheKey]; ok {
		e.mutex.RUnlock()
		e.applyIPInfo(event, cached.(IPInfo), direction)
		return nil
	}
	e.mutex.RUnlock()

	// Get geolocation data
	geoData, err := e.geoIPDB.Lookup(ip)
	if err != nil {
		return err
	}

	// Get threat intelligence data
	threatInfo, err := e.reputationDB.LookupIP(ctx, ip)
	if err != nil {
		return err
	}

	// Combine information
	ipInfo := IPInfo{
		Country:    geoData.Country,
		City:       geoData.City,
		ASN:        geoData.ASN,
		Reputation: threatInfo.Score,
		Categories: threatInfo.Categories,
		LastSeen:   threatInfo.LastSeen,
	}

	// Cache the result
	e.mutex.Lock()
	e.cache[cacheKey] = ipInfo
	e.mutex.Unlock()

	// Apply the information to the event
	e.applyIPInfo(event, ipInfo, direction)

	return nil
}

// calculateSeverity determines event severity based on enriched data
func (e *LogEnricher) calculateSeverity(event *entity.SecurityEvent) {
	// Start with a base score
	score := 0.0

	// Check IP reputation
	if strings.Contains(event.Labels["source_reputation"], "malicious") {
		score += 0.4
	}
	if strings.Contains(event.Labels["dest_reputation"], "malicious") {
		score += 0.3
	}

	// Check action type
	switch strings.ToLower(event.Action) {
	case "block", "deny", "alert":
		score += 0.2
	case "warning":
		score += 0.1
	}

	// Set severity based on final score
	switch {
	case score >= 0.7:
		event.Severity = "critical"
	case score >= 0.5:
		event.Severity = "high"
	case score >= 0.3:
		event.Severity = "medium"
	default:
		event.Severity = "low"
	}
}

// IPInfo represents enriched IP address information
type IPInfo struct {
	Country    string
	City       string
	ASN        string
	Reputation float32
	Categories []string
	LastSeen   string
}

// Apply IP information to the event
func (e *LogEnricher) applyIPInfo(event *entity.SecurityEvent, info IPInfo, direction string) {
	prefix := direction + "_"

	// Add labels
	if event.Labels == nil {
		event.Labels = make([]string, 0)
	}

	event.Labels = append(event.Labels,
		prefix+"country:"+info.Country,
		prefix+"city:"+info.City,
		prefix+"asn:"+info.ASN,
	)

	for _, category := range info.Categories {
		event.Labels = append(event.Labels, prefix+"category:"+category)
	}
}
