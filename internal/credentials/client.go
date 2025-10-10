package credentials

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"redmantis/internal/assets"
)

// ScanRequest represents the request to credential scanner API
type ScanRequest struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ScanResponse represents the response from credential scanner API
type ScanResponse struct {
	Target    string                  `json:"target"`
	Service   string                  `json:"service"`
	Detection ServiceDetection        `json:"detection"`
	Results   []assets.CredentialTest `json:"results"`
	Summary   struct {
		TotalTests int  `json:"total_tests"`
		Successful int  `json:"successful"`
		Failed     int  `json:"failed"`
		Vulnerable bool `json:"vulnerable"`
	} `json:"summary"`
}

// ServiceDetection represents detailed service detection results
type ServiceDetection struct {
	Service     string `json:"service"`
	Confidence  int    `json:"confidence"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

// ServicePattern represents a regex pattern for service detection
type ServicePattern struct {
	Regex       string `json:"regex"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

// ServicePatternData contains all patterns for a service
type ServicePatternData struct {
	CredentialService string           `json:"credential_service"`
	Patterns          []ServicePattern `json:"patterns"`
}

// ServiceDetectionConfig holds the complete service detection configuration
type ServiceDetectionConfig struct {
	ServicePatterns    map[string]ServicePatternData `json:"service_patterns"`
	PortServiceMapping map[string]string             `json:"port_service_mapping"`
	ServiceAliases     map[string]string             `json:"service_aliases"`
}

// Client represents a credential testing client
type Client struct {
	apiURL        string
	httpClient    *http.Client
	serviceConfig *ServiceDetectionConfig
}

// NewClient creates a new credential testing client
func NewClient(apiURL string) *Client {
	return &Client{
		apiURL:        apiURL,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		serviceConfig: loadServiceDetectionConfig(),
	}
}

// loadServiceDetectionConfig loads service detection configuration from JSON file
func loadServiceDetectionConfig() *ServiceDetectionConfig {
	// Try to load from JSON file
	configPath := "service-detection-config.json"
	if file, err := os.Open(configPath); err == nil {
		defer file.Close()
		decoder := json.NewDecoder(file)
		var config ServiceDetectionConfig
		if err := decoder.Decode(&config); err == nil {
			log.Printf("Loaded service detection config from %s", configPath)
			return &config
		} else {
			log.Printf("Warning: Failed to parse service detection config: %v", err)
		}
	} else {
		log.Printf("Warning: Service detection config not found at %s: %v", configPath, err)
	}

	// Return fallback configuration
	return &ServiceDetectionConfig{
		ServicePatterns: make(map[string]ServicePatternData),
		PortServiceMapping: map[string]string{
			"21": "ftp", "22": "ssh", "139": "smb", "445": "smb",
			"1433": "mssql", "1521": "oracle", "3306": "mysql",
			"3389": "rdp", "5432": "postgresql", "6379": "redis", "27017": "mongodb",
		},
		ServiceAliases: map[string]string{
			"mariadb": "mysql", "postgres": "postgresql", "samba": "smb",
		},
	}
}

// detectServiceWithConfidence performs intelligent service detection using regex patterns
func (c *Client) detectServiceWithConfidence(ip string, port int, banner string) ServiceDetection {
	bestMatch := ServiceDetection{Service: "unknown", Confidence: 0}

	// Try regex-based detection first (higher accuracy)
	if banner != "" {
		for serviceName, serviceData := range c.serviceConfig.ServicePatterns {
			for _, pattern := range serviceData.Patterns {
				regex, err := regexp.Compile(pattern.Regex)
				if err != nil {
					log.Printf("Warning: Invalid regex pattern for %s: %v", serviceName, err)
					continue
				}

				matches := regex.FindStringSubmatch(banner)
				if len(matches) > 0 {
					confidence := pattern.Confidence
					version := ""

					// Extract version if available in match groups
					if len(matches) > 1 {
						version = matches[1]
					}

					if confidence > bestMatch.Confidence {
						credentialService := serviceData.CredentialService
						if credentialService == "" {
							credentialService = serviceName
						}

						bestMatch = ServiceDetection{
							Service:     credentialService,
							Confidence:  confidence,
							Version:     version,
							Description: pattern.Description,
						}
					}
				}
			}
		}
	}

	// If no high-confidence match, try port-based detection
	if bestMatch.Confidence < 85 {
		if portService, exists := c.serviceConfig.PortServiceMapping[fmt.Sprintf("%d", port)]; exists {
			// Apply service aliases
			if alias, hasAlias := c.serviceConfig.ServiceAliases[portService]; hasAlias {
				portService = alias
			}

			if bestMatch.Confidence < 70 {
				bestMatch = ServiceDetection{
					Service:     portService,
					Confidence:  70,
					Description: "Port-based detection",
				}
			}
		}
	}

	return bestMatch
}

// ScanService performs credential testing for a specific host and port
func (c *Client) ScanService(ip string, port int, service string) (*ScanResponse, error) {
	request := ScanRequest{
		IP:      ip,
		Port:    port,
		Service: service,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.apiURL+"/scan", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var response ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// ScanAllAssets performs credential testing for all discovered hosts
func (c *Client) ScanAllAssets(assetList []assets.Asset) map[string][]assets.CredentialTest {
	fmt.Println("\n=== Phase 8: Credential Testing ===")
	fmt.Println("Testing default credentials on discovered services...")

	credentialResults := make(map[string][]assets.CredentialTest)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Worker pool for credential testing
	maxWorkers := 10
	semaphore := make(chan struct{}, maxWorkers)

	totalTests := 0
	for _, asset := range assetList {
		if len(asset.Ports) > 0 {
			totalTests += len(asset.Ports)
		}
	}

	fmt.Printf("Found %d open ports across %d hosts to test\n", totalTests, len(assetList))

	testedCount := 0
	for _, asset := range assetList {
		if len(asset.Ports) == 0 {
			continue
		}

		for _, port := range asset.Ports {
			wg.Add(1)
			go func(asset assets.Asset, port assets.PortScanResult) {
				defer wg.Done()

				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// Intelligent service detection
				service := port.Service
				var serviceDetection ServiceDetection

				if service == "" || service == "unknown" {
					// Get banner if not already available
					banner := port.Banner
					if banner == "" {
						banner = grabBanner(asset.Address, port.Number)
					}

					// Use intelligent service detection
					serviceDetection = c.detectServiceWithConfidence(asset.Address, port.Number, banner)
					service = serviceDetection.Service
				} else {
					// Use existing service but create detection result
					serviceDetection = ServiceDetection{
						Service:     service,
						Confidence:  80,
						Description: "Pre-detected service",
					}
				}

				// Skip if service is unknown or not supported
				supportedServices := []string{"ssh", "ftp", "smb", "redis", "postgresql", "mysql", "mssql", "oracle", "mongodb", "rdp", "telnet", "http", "https", "smtp", "pop3", "imap", "ldap", "snmp", "vnc"}
				isSupported := false
				for _, supported := range supportedServices {
					if strings.ToLower(service) == supported {
						isSupported = true
						break
					}
				}

				if !isSupported || service == "unknown" {
					if serviceDetection.Confidence > 0 {
						log.Printf("Skipping unsupported service: %s (confidence: %d) on %s:%d", service, serviceDetection.Confidence, asset.Address, port.Number)
					}
					return
				}

				// Log service detection details
				if serviceDetection.Version != "" {
					fmt.Printf("Testing credentials for %s:%d (%s v%s, confidence: %d%%)...\n", asset.Address, port.Number, service, serviceDetection.Version, serviceDetection.Confidence)
				} else {
					fmt.Printf("Testing credentials for %s:%d (%s, confidence: %d%%)...\n", asset.Address, port.Number, service, serviceDetection.Confidence)
				}

				response, err := c.ScanService(asset.Address, port.Number, service)
				if err != nil {
					fmt.Printf("Warning: Credential test failed for %s:%d - %v\n", asset.Address, port.Number, err)
					return
				}

				mu.Lock()
				credentialResults[asset.Address] = append(credentialResults[asset.Address], response.Results...)
				mu.Unlock()

				testedCount++
				if len(response.Results) > 0 {
					fmt.Printf("✓ Found %d vulnerable credentials for %s:%d\n", len(response.Results), asset.Address, port.Number)
					for _, result := range response.Results {
						if result.Success {
							fmt.Printf("  - %s:%s (%s)\n", result.Username, result.Password, result.Service)
						}
					}
				} else {
					fmt.Printf("✗ No vulnerable credentials found for %s:%d\n", asset.Address, port.Number)
				}
			}(asset, port)
		}
	}

	wg.Wait()

	// Summary
	totalVulnerable := 0
	for _, results := range credentialResults {
		for _, result := range results {
			if result.Success {
				totalVulnerable++
			}
		}
	}

	fmt.Printf("\nCredential testing completed:\n")
	fmt.Printf("  - Tested %d services\n", testedCount)
	fmt.Printf("  - Found %d vulnerable credentials\n", totalVulnerable)
	fmt.Printf("  - Affected hosts: %d\n", len(credentialResults))

	return credentialResults
}

// grabBanner attempts to grab service banner for detection
func grabBanner(ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Different banner grabbing strategies for different port ranges
	switch {
	case port == 21 || port == 25 || port == 110 || port == 143 || port == 220:
		// Services that send greeting automatically
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return string(buffer[:n])
		}

	case port == 22:
		// SSH
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return string(buffer[:n])
		}

	case port == 80 || port == 443 || port == 8080 || port == 8443:
		// HTTP services
		httpReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", ip)
		conn.Write([]byte(httpReq))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return string(buffer[:n])
		}

	default:
		// Generic banner grab
		conn.Write([]byte("\r\n"))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return string(buffer[:n])
		}
	}

	return ""
}
