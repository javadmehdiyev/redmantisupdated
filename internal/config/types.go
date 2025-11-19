package config

import "time"

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

	NetBIOS struct {
		Enabled bool   `json:"enabled"`
		Timeout string `json:"timeout"`
		Workers int    `json:"workers"`
	} `json:"netbios"`

	MDNS struct {
		Enabled     bool   `json:"enabled"`
		Timeout     string `json:"timeout"`
		Retries     int    `json:"retries"`
		Concurrency int    `json:"concurrency"`
	} `json:"mdns"`

	PortScan struct {
		Enabled bool   `json:"enabled"`
		Timeout string `json:"timeout"`
		Workers int    `json:"workers"`
	} `json:"port_scan"`

	Files struct {
		IPListFile   string `json:"ip_list_file"`
		OutputFile   string `json:"output_file"`
		SettingsFile string `json:"settings_file"`
	} `json:"files"`

	Credentials struct {
		Enabled      bool   `json:"enabled"`
		SettingsFile string `json:"settings_file"`
		Timeout      string `json:"timeout"`
		Workers      int    `json:"workers"`
		TestDefault  bool   `json:"test_default_creds"`
	} `json:"credentials"`

	Nuclei struct {
		Enabled     bool     `json:"enabled"`
		Severity    []string `json:"severity"`
		RateLimit   int      `json:"rate_limit"`
		Concurrency int      `json:"concurrency"`
		Timeout     string   `json:"timeout"`
	} `json:"nuclei"`
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

// GetNetBIOSTimeout returns the NetBIOS timeout as a time.Duration
func (c *Config) GetNetBIOSTimeout() time.Duration {
	timeout, err := time.ParseDuration(c.NetBIOS.Timeout)
	if err != nil {
		// Default to 3 seconds if parsing fails
		return 3 * time.Second
	}
	return timeout
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

// GetCredentialTimeout returns the credential testing timeout as a time.Duration
func (c *Config) GetCredentialTimeout() time.Duration {
	timeout, err := time.ParseDuration(c.Credentials.Timeout)
	if err != nil {
		// Default to 10 seconds if parsing fails
		return 10 * time.Second
	}
	return timeout
}

// GetMDNSTimeout returns the mDNS timeout as a time.Duration
func (c *Config) GetMDNSTimeout() time.Duration {
	timeout, err := time.ParseDuration(c.MDNS.Timeout)
	if err != nil {
		// Default to 12 seconds if parsing fails
		return 12 * time.Second
	}
	return timeout
}

// GetNucleiTimeout returns the Nuclei scan timeout as a time.Duration
func (c *Config) GetNucleiTimeout() time.Duration {
	if c.Nuclei.Timeout == "" {
		return 30 * time.Second
	}
	timeout, err := time.ParseDuration(c.Nuclei.Timeout)
	if err != nil {
		// Default to 30 seconds if parsing fails
		return 30 * time.Second
	}
	return timeout
}
