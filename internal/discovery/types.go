package discovery

import (
	"net"
	"sync"
	"time"

	"redmantis/internal/network"
)

// ArpScanResults holds the results of an ARP scan
type ArpScanResults struct {
	Hosts    []network.HostStatus
	Duration time.Duration
}

// PingScanResults represents the results of a ping scan
type PingScanResults struct {
	Hosts    []network.HostStatus
	Duration time.Duration
}

// SynScanResults represents the results of a SYN scan
type SynScanResults struct {
	Hosts    []network.HostStatus
	Duration time.Duration
}

// PassiveDiscoveryResults represents the results of passive discovery
type PassiveDiscoveryResults struct {
	Hosts    map[string]network.HostStatus
	Duration time.Duration
}

// ServiceInfo represents a discovered mDNS service
type ServiceInfo struct {
	ServiceType string   `json:"service_type"`
	ServiceName string   `json:"service_name"`
	Hostname    string   `json:"hostname"`
	Port        int      `json:"port"`
	IPv4        []string `json:"ipv4_addresses"`
	IPv6        []string `json:"ipv6_addresses"`
	TXTRecords  []string `json:"txt_records"`
	Info        string   `json:"info,omitempty"`
}

// HostInfo represents a discovered host
type HostInfo struct {
	Hostname string   `json:"hostname"`
	IPv4     []string `json:"ipv4_addresses"`
	IPv6     []string `json:"ipv6_addresses"`
	Services []string `json:"services"`
}

// DiscoveryResult represents the complete discovery results
type DiscoveryResult struct {
	Services     []ServiceInfo       `json:"services"`
	Hosts        []HostInfo          `json:"hosts"`
	ServiceTypes map[string]int      `json:"service_type_counts"`
	Summary      DiscoverySummary    `json:"summary"`
	Timestamp    time.Time           `json:"timestamp"`
	Duration     time.Duration       `json:"duration"`
	metadata     map[string][]net.IP // Internal use only
	mutex        sync.RWMutex        // Thread safety
}

// DiscoverySummary provides statistical summary
type DiscoverySummary struct {
	TotalServices     int    `json:"total_services"`
	TotalHosts        int    `json:"total_hosts"`
	TotalServiceTypes int    `json:"total_service_types"`
	MostCommonService string `json:"most_common_service"`
	IPv4Count         int    `json:"ipv4_count"`
	IPv6Count         int    `json:"ipv6_count"`
}
