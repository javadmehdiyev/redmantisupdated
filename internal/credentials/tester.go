package credentials

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"redmantis/internal/assets"
	"redmantis/internal/config"
)

// CredentialTester manages credential testing for discovered assets
type CredentialTester struct {
	config   *config.Config
	settings *CredentialSettings
	timeout  time.Duration
}

// NewTester creates a new credential tester
func NewTester(cfg *config.Config) (*CredentialTester, error) {
	// Load settings from settings.json
	settings, err := LoadSettings(cfg.Credentials.SettingsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential settings: %w", err)
	}

	return &CredentialTester{
		config:   cfg,
		settings: settings,
		timeout:  cfg.GetCredentialTimeout(),
	}, nil
}

// TestAllAssets tests credentials for all assets discovered by the scanner
func (t *CredentialTester) TestAllAssets(assetList []assets.Asset) map[string][]assets.CredentialTest {
	if !t.config.Credentials.Enabled || !t.config.Credentials.TestDefault {
		fmt.Println("\n=== Phase 8: Credential Testing ===")
		fmt.Println("Credential testing is disabled in configuration, skipping...")
		return make(map[string][]assets.CredentialTest)
	}

	fmt.Println("\n=== Phase 8: Credential Testing ===")
	fmt.Printf("Testing default credentials from %s...\n", t.config.Credentials.SettingsFile)
	fmt.Printf("Configuration: timeout=%v, workers=%d\n", t.timeout, t.config.Credentials.Workers)

	results := make(map[string][]assets.CredentialTest)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Worker pool
	semaphore := make(chan struct{}, t.config.Credentials.Workers)

	totalTests := 0
	for _, asset := range assetList {
		totalTests += len(asset.Ports)
	}

	fmt.Printf("Found %d open ports across %d assets to test\n", totalTests, len(assetList))

	testedCount := 0
	vulnerableCount := 0

	for _, asset := range assetList {
		if len(asset.Ports) == 0 {
			continue
		}

		for _, port := range asset.Ports {
			if port.State != "open" {
				continue
			}

			wg.Add(1)
			semaphore <- struct{}{} // Acquire

			go func(asset assets.Asset, port assets.PortScanResult) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release

				// Identify service
				service := t.identifyService(port.Number, port.Service)
				if service == "unknown" {
					return
				}

				// Build credentials for this service
				creds := BuildCredentialList(t.settings, service)
				if len(creds) == 0 {
					return
				}

				fmt.Printf("Testing %s:%d (%s) with %d credential combinations...\n",
					asset.Address, port.Number, service, len(creds))

				// Test credentials based on service type
				testResults := t.testService(asset.Address, port.Number, service, creds)

				if len(testResults) > 0 {
					mu.Lock()
					results[asset.Address] = append(results[asset.Address], testResults...)
					vulnerableCount++
					mu.Unlock()

					fmt.Printf("✓ Found vulnerable credentials for %s:%d (%s)\n",
						asset.Address, port.Number, service)
					for _, result := range testResults {
						fmt.Printf("  - %s:%s\n", result.Username, result.Password)
					}
				} else {
					fmt.Printf("✗ No vulnerable credentials found for %s:%d (%s)\n",
						asset.Address, port.Number, service)
				}

				mu.Lock()
				testedCount++
				mu.Unlock()
			}(asset, port)
		}
	}

	wg.Wait()

	fmt.Printf("\nCredential testing completed:\n")
	fmt.Printf("  - Services tested: %d\n", testedCount)
	fmt.Printf("  - Vulnerable services: %d\n", vulnerableCount)
	fmt.Printf("  - Affected assets: %d\n", len(results))

	return results
}

// identifyService identifies the service type from port number and service name
func (t *CredentialTester) identifyService(port int, serviceName string) string {
	serviceLower := strings.ToLower(serviceName)

	// Check service name first
	if strings.Contains(serviceLower, "ssh") {
		return "ssh"
	}
	if strings.Contains(serviceLower, "ftp") {
		return "ftp"
	}
	if strings.Contains(serviceLower, "mysql") || strings.Contains(serviceLower, "mariadb") {
		return "mysql"
	}
	if strings.Contains(serviceLower, "postgresql") || strings.Contains(serviceLower, "postgres") {
		return "postgresql"
	}
	if strings.Contains(serviceLower, "mssql") || strings.Contains(serviceLower, "sql server") {
		return "mssql"
	}
	if strings.Contains(serviceLower, "mongodb") || strings.Contains(serviceLower, "mongo") {
		return "mongodb"
	}
	if strings.Contains(serviceLower, "redis") {
		return "redis"
	}
	if strings.Contains(serviceLower, "smb") || strings.Contains(serviceLower, "microsoft-ds") ||
		strings.Contains(serviceLower, "netbios") {
		return "smb"
	}
	if strings.Contains(serviceLower, "rdp") || strings.Contains(serviceLower, "ms-wbt-server") {
		return "rdp"
	}
	if strings.Contains(serviceLower, "telnet") {
		return "telnet"
	}
	if strings.Contains(serviceLower, "http") {
		if port == 443 || port == 8443 {
			return "https"
		}
		return "http"
	}

	// Fallback to port-based detection
	portServiceMap := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		80:    "http",
		139:   "smb",
		443:   "https",
		445:   "smb",
		1433:  "mssql",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http",
		8443:  "https",
		27017: "mongodb",
	}

	if service, found := portServiceMap[port]; found {
		return service
	}

	return "unknown"
}

// testService tests credentials for a specific service
func (t *CredentialTester) testService(ip string, port int, service string, creds []Credential) []assets.CredentialTest {
	switch service {
	case "ssh":
		return TestSSH(ip, port, creds, t.timeout)
	case "ftp":
		return TestFTP(ip, port, creds, t.timeout)
	case "mysql":
		return TestMySQL(ip, port, creds, t.timeout)
	case "postgresql":
		return TestPostgreSQL(ip, port, creds, t.timeout)
	case "http":
		return TestHTTP(ip, port, creds, t.timeout, false)
	case "https":
		return TestHTTP(ip, port, creds, t.timeout, true)
	case "telnet":
		return TestTelnet(ip, port, creds, t.timeout)
	case "smb":
		return TestSMB(ip, port, creds, t.timeout)
	default:
		// Unsupported service
		return []assets.CredentialTest{}
	}
}
