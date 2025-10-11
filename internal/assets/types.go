package assets

import "time"

// Asset represents a complete asset inventory record
type Asset struct {
	Address    string           `json:"address"`
	Hostname   string           `json:"hostname"`
	Mac        string           `json:"mac"`
	MacVendor  string           `json:"mac_vendor"`
	Type       string           `json:"type"`
	OS         string           `json:"os"`
	Hardware   string           `json:"hardware"`
	Date       time.Time        `json:"date"`
	Ports      []PortScanResult `json:"ports"`
	CredTest   []CredentialTest `json:"credential_tests"`
	Screenshot string           `json:"screenshot,omitempty"`
}

// PortScanResult represents the final port scan result
type PortScanResult struct {
	Number    int    `json:"number"`
	Service   string `json:"service"`
	Banner    string `json:"banner"`
	State     string `json:"state"`
	Transport string `json:"transport"`
}

// CredentialTest represents credential testing information
type CredentialTest struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
}

// PortResult represents the result from nmap scan (internal use)
type PortResult struct {
	Port      int
	State     bool
	Service   string
	Banner    string
	Protocol  string
	IPAddress string
}
