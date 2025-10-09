package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config represents the application configuration
type Config struct {
	Service struct {
		Name         string `json:"name"`
		RunAsDaemon  bool   `json:"run_as_daemon"`
		ScanInterval string `json:"scan_interval"`
		AutoStart    bool   `json:"auto_start"`
	} `json:"service"`

	Network struct {
		Interface        string `json:"interface"`
		AutoDetectLocal  bool   `json:"auto_detect_local"`
		DefaultCIDR      string `json:"default_cidr"`
		ScanLocalNetwork bool   `json:"scan_local_network"`
		ScanFileList     bool   `json:"scan_file_list"`
	} `json:"network"`

	ARP struct {
		Enabled   bool   `json:"enabled"`
		Timeout   string `json:"timeout"`
		Workers   int    `json:"workers"`
		RateLimit string `json:"rate_limit"`
	} `json:"arp"`

	PortScan struct {
		Enabled bool   `json:"enabled"`
		Timeout string `json:"timeout"`
		Workers int    `json:"workers"`
	} `json:"port_scan"`

	Files struct {
		IPListFile string `json:"ip_list_file"`
		OutputFile string `json:"output_file"`
	} `json:"files"`
}

// LoadConfig loads configuration from the specified JSON file
func LoadConfig(configPath string) (*Config, error) {
	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Parse the JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &config, nil
}

// GetARPTimeout returns the ARP timeout as a time.Duration
func (c *Config) GetARPTimeout() time.Duration {
	timeout, err := time.ParseDuration(c.ARP.Timeout)
	if err != nil {
		// Default to 2 seconds if parsing fails
		return 2 * time.Second
	}
	return timeout
}

// GetPortScanTimeout returns the port scan timeout as a time.Duration
func (c *Config) GetPortScanTimeout() time.Duration {
	timeout, err := time.ParseDuration(c.PortScan.Timeout)
	if err != nil {
		// Default to 2 seconds if parsing fails
		return 2 * time.Second
	}
	return timeout
}

// GetARPRateLimit returns the ARP rate limit as a time.Duration
func (c *Config) GetARPRateLimit() time.Duration {
	rateLimit, err := time.ParseDuration(c.ARP.RateLimit)
	if err != nil {
		// Default to 50ms if parsing fails
		return 50 * time.Millisecond
	}
	return rateLimit
}

// GetScanInterval returns the service scan interval as a time.Duration
func (c *Config) GetScanInterval() time.Duration {
	interval, err := time.ParseDuration(c.Service.ScanInterval)
	if err != nil {
		// Default to 5 minutes if parsing fails
		return 5 * time.Minute
	}
	return interval
}
