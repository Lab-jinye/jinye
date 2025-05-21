package entity

// SecurityAnalysis represents the analysis result from QianXin's security LLM
type SecurityAnalysis struct {
	EventID        string  `json:"event_id"`
	ThreatLevel    string  `json:"threat_level"`
	ThreatType     string  `json:"threat_type"`
	Recommendation string  `json:"recommendation"`
	Confidence     float64 `json:"confidence"`
	Timestamp      int64   `json:"timestamp"`
}

// NewSecurityAnalysis creates a new instance of SecurityAnalysis
func NewSecurityAnalysis(eventID string) *SecurityAnalysis {
	return &SecurityAnalysis{
		EventID:   eventID,
		Timestamp: time.Now().Unix(),
	}
}

// IsHighRisk checks if the analysis indicates a high-risk threat
func (a *SecurityAnalysis) IsHighRisk() bool {
	return a.ThreatLevel == "high" || a.ThreatLevel == "critical"
}

// IsMediumRisk checks if the analysis indicates a medium-risk threat
func (a *SecurityAnalysis) IsMediumRisk() bool {
	return a.ThreatLevel == "medium"
}

// IsLowRisk checks if the analysis indicates a low-risk threat
func (a *SecurityAnalysis) IsLowRisk() bool {
	return a.ThreatLevel == "low"
}