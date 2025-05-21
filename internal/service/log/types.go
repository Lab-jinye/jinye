package log

import (
	"context"
	"time"
)

// GeoIPDatabase represents a geolocation database
type GeoIPDatabase interface {
	// Lookup retrieves geolocation information for an IP address
	Lookup(ip string) (*GeoData, error)
}

// ThreatDB represents a threat intelligence database
type ThreatDB interface {
	// LookupIP retrieves threat information for an IP address
	LookupIP(ctx context.Context, ip string) (*ThreatInfo, error)
}

// GeoData represents geolocation information
type GeoData struct {
	Country   string    `json:"country"`
	City      string    `json:"city"`
	Region    string    `json:"region"`
	ASN       string    `json:"asn"`
	ASNOrg    string    `json:"asn_org"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ThreatInfo represents threat intelligence information
type ThreatInfo struct {
	Score      float32   `json:"score"`
	Categories []string  `json:"categories"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   string    `json:"last_seen"`
	References []string  `json:"references"`
	Confidence float32   `json:"confidence"`
}
