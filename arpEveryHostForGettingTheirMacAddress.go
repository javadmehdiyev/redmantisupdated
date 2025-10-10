package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// HostStatus represents a host with its IP address, MAC address, and alive status
type HostStatus struct {
	IPAddress  string
	MACAddress string
	IsAlive    bool
}

// ArpScanResults holds the results of an ARP scan
type ArpScanResults struct {
	Hosts    []HostStatus
	Duration time.Duration
}

// CredentialScanRequest represents the request to credential scanner API
type CredentialScanRequest struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// CredentialScanResponse represents the response from credential scanner API
type CredentialScanResponse struct {
	Target    string           `json:"target"`
	Service   string           `json:"service"`
	Detection ServiceDetection `json:"detection"`
	Results   []CredentialTest `json:"results"`
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

// performARPScan performs comprehensive ARP scanning to discover live hosts on the network.
// Technique: Uses raw packet capture with gopacket library to send ARP requests and capture responses.
// Implements batch processing with retry logic and progressive timeouts for thorough discovery.
// Returns ArpScanResults containing all discovered hosts with their MAC addresses.
func performARPScan(hosts []Host, iface NetworkInfo, timeout time.Duration) (ArpScanResults, error) {
	start := time.Now()

	handle, err := pcap.OpenLive(iface.InterfaceName, 65536, true, timeout)
	if err != nil {
		return ArpScanResults{}, fmt.Errorf("failed to open device %s: %w", iface.InterfaceName, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("arp")
	if err != nil {
		return ArpScanResults{}, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	ifaceObj, err := net.InterfaceByName(iface.InterfaceName)
	if err != nil {
		return ArpScanResults{}, fmt.Errorf("failed to get interface %s: %w", iface.InterfaceName, err)
	}
	srcMAC := ifaceObj.HardwareAddr

	srcIP := net.ParseIP(iface.IPAddress).To4()
	if srcIP == nil {
		return ArpScanResults{}, fmt.Errorf("failed to parse source IP %s", iface.IPAddress)
	}

	var (
		results = make(map[string]HostStatus)
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	stopChan := make(chan struct{})
	packetsChan := make(chan gopacket.Packet, 100)

	go func() {
		defer close(packetsChan)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-stopChan:
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					continue
				}
				packetsChan <- packet
			}
		}
	}()

	go func() {
		for packet := range packetsChan {
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			ip := net.IP(arp.SourceProtAddress).String()
			mac := net.HardwareAddr(arp.SourceHwAddress).String()

			mu.Lock()
			results[ip] = HostStatus{
				IPAddress:  ip,
				MACAddress: mac,
				IsAlive:    true,
			}
			mu.Unlock()
		}
	}()

	for _, host := range hosts {
		results[host.IPAddress] = HostStatus{
			IPAddress:  host.IPAddress,
			MACAddress: "unknown",
			IsAlive:    false,
		}
	}

	sendARPRequest := func(hostIP string) error {
		dstIP := net.ParseIP(hostIP).To4()
		if dstIP == nil {
			return fmt.Errorf("failed to parse destination IP %s", hostIP)
		}

		eth := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}

		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(srcMAC),
			SourceProtAddress: []byte(srcIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(dstIP),
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err := gopacket.SerializeLayers(buffer, opts, &eth, &arp)
		if err != nil {
			return fmt.Errorf("failed to serialize ARP packet: %w", err)
		}

		return handle.WritePacketData(buffer.Bytes())
	}

	fmt.Println("Sending ARP requests to all hosts...")

	maxRetries := 3
	batchSize := 25
	initialDelay := 800 * time.Millisecond
	retryDelays := []time.Duration{
		2 * time.Second,
		3 * time.Second,
		5 * time.Second,
	}

	var aliveCountHistory []int

	countAliveHosts := func() int {
		mu.Lock()
		defer mu.Unlock()
		count := 0
		for _, status := range results {
			if status.IsAlive {
				count++
			}
		}
		return count
	}

	for i := 0; i < len(hosts); i += batchSize {
		end := i + batchSize
		if end > len(hosts) {
			end = len(hosts)
		}

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(host Host) {
				defer wg.Done()
				err := sendARPRequest(host.IPAddress)
				if err != nil {
					fmt.Printf("Warning: Failed to send ARP packet to %s: %v\n", host.IPAddress, err)
				}
			}(hosts[j])
		}

		wg.Wait()
		time.Sleep(initialDelay)
	}

	time.Sleep(4 * time.Second)

	initialAliveCount := countAliveHosts()
	aliveCountHistory = append(aliveCountHistory, initialAliveCount)
	fmt.Printf("Initial scan: Found %d hosts\n", initialAliveCount)

	for retry := 1; retry <= maxRetries; retry++ {
		var nonRespondingHosts []Host
		mu.Lock()
		for _, host := range hosts {
			if status, exists := results[host.IPAddress]; exists && !status.IsAlive {
				nonRespondingHosts = append(nonRespondingHosts, host)
			}
		}
		mu.Unlock()

		if len(nonRespondingHosts) == 0 {
			fmt.Println("All hosts have responded, no need for retries.")
			break
		}

		respondingPercent := float64(len(hosts)-len(nonRespondingHosts)) / float64(len(hosts)) * 100

		fmt.Printf("Retry #%d: %.1f%% of hosts have responded. Sending ARP requests to %d non-responding hosts...\n",
			retry, respondingPercent, len(nonRespondingHosts))

		currentRetryDelay := retryDelays[0]
		if retry-1 < len(retryDelays) {
			currentRetryDelay = retryDelays[retry-1]
		} else if len(retryDelays) > 0 {
			currentRetryDelay = retryDelays[len(retryDelays)-1]
		}

		fmt.Printf("Using timeout of %.1f seconds for retry #%d\n", currentRetryDelay.Seconds(), retry)

		for i := 0; i < len(nonRespondingHosts); i += batchSize {
			end := i + batchSize
			if end > len(nonRespondingHosts) {
				end = len(nonRespondingHosts)
			}

			for j := i; j < end; j++ {
				wg.Add(1)
				go func(host Host) {
					defer wg.Done()
					packetCount := retry + 1
					for p := 0; p < packetCount; p++ {
						_ = sendARPRequest(host.IPAddress)
						time.Sleep(50 * time.Millisecond)
					}
				}(nonRespondingHosts[j])
			}

			wg.Wait()
			time.Sleep(currentRetryDelay)
		}

		waitTime := time.Duration(retry*2+1) * time.Second
		fmt.Printf("Waiting %.1f seconds for responses...\n", waitTime.Seconds())
		time.Sleep(waitTime)

		currentAliveCount := countAliveHosts()
		newHostsDiscovered := currentAliveCount - aliveCountHistory[len(aliveCountHistory)-1]
		aliveCountHistory = append(aliveCountHistory, currentAliveCount)

		fmt.Printf("Retry #%d: Found %d new hosts (total: %d)\n",
			retry, newHostsDiscovered, currentAliveCount)
	}

	time.Sleep(timeout + 2*time.Second)

	fmt.Println("\nScan Summary:")
	fmt.Printf("Initial scan: %d hosts\n", aliveCountHistory[0])
	for i := 1; i < len(aliveCountHistory); i++ {
		fmt.Printf("Retry #%d: +%d hosts (total: %d)\n",
			i, aliveCountHistory[i]-aliveCountHistory[i-1], aliveCountHistory[i])
	}

	close(stopChan)

	var hostStatuses []HostStatus
	for _, status := range results {
		hostStatuses = append(hostStatuses, status)
	}

	return ArpScanResults{
		Hosts:    hostStatuses,
		Duration: time.Since(start),
	}, nil
}

// LoadHostsFromFile loads hosts from a text file containing IP addresses and CIDR ranges
// Each line can contain either an IP address or a CIDR range
// Lines starting with # are treated as comments and ignored
func LoadHostsFromFile(filename string) ([]Host, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var hosts []Host
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(line, "/") {
			cidrHosts, err := expandCIDR(line)
			if err != nil {
				fmt.Printf("Warning: Invalid CIDR on line %d: %s (%v)\n", lineNum, line, err)
				continue
			}
			hosts = append(hosts, cidrHosts...)
		} else {
			// Treat as individual IP address
			if ip := net.ParseIP(line); ip != nil {
				hosts = append(hosts, Host{IPAddress: line})
			} else {
				fmt.Printf("Warning: Invalid IP address on line %d: %s\n", lineNum, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return hosts, nil
}

// expandCIDR expands a CIDR range into individual Host entries
func expandCIDR(cidr string) ([]Host, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Get the IP and mask
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("not an IPv4 network: %s", cidr)
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()

	// Calculate number of hosts (excluding network and broadcast for normal networks)
	numHostBits := bits - ones
	if numHostBits > 16 { // Limit to avoid memory issues with huge ranges like /8
		return nil, fmt.Errorf("CIDR range too large (more than /16): %s", cidr)
	}

	var hosts []Host

	// Handle special cases
	if ones >= 31 {
		// /31 and /32 networks - use all addresses
		hosts = append(hosts, Host{IPAddress: ipNet.IP.String()})
		if ones == 31 {
			// For /31, add the other address too
			nextIP := make(net.IP, len(ipNet.IP))
			copy(nextIP, ipNet.IP)
			nextIP[3]++
			hosts = append(hosts, Host{IPAddress: nextIP.String()})
		}
		return hosts, nil
	}

	// Convert IP to uint32 for easier manipulation
	ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	maskUint := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	networkUint := ipUint & maskUint

	// Generate all host addresses (skip network and broadcast)
	numHosts := (1 << numHostBits) - 2 // Exclude network and broadcast
	for i := 1; i <= numHosts; i++ {
		hostUint := networkUint + uint32(i)
		hostIP := net.IPv4(
			byte(hostUint>>24),
			byte(hostUint>>16),
			byte(hostUint>>8),
			byte(hostUint),
		)
		hosts = append(hosts, Host{IPAddress: hostIP.String()})
	}

	return hosts, nil
}

// removeDuplicateHosts removes duplicate hosts based on IP address
func removeDuplicateHosts(hosts []Host) []Host {
	seen := make(map[string]bool)
	var unique []Host

	for _, host := range hosts {
		if !seen[host.IPAddress] {
			seen[host.IPAddress] = true
			unique = append(unique, host)
		}
	}

	return unique
}

// performCredentialScan performs credential testing for a specific host and port
// Technique: Sends HTTP POST request to credential scanner API with host and port information
// Implements timeout handling and error recovery for robust credential testing
// Returns CredentialScanResponse containing test results and vulnerability status
func performCredentialScan(ip string, port int, service string, apiURL string) (*CredentialScanResponse, error) {
	request := CredentialScanRequest{
		IP:      ip,
		Port:    port,
		Service: service,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(apiURL+"/scan", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var response CredentialScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
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
func detectServiceWithConfidence(ip string, port int, banner string, config *ServiceDetectionConfig) ServiceDetection {
	bestMatch := ServiceDetection{Service: "unknown", Confidence: 0}

	// Try regex-based detection first (higher accuracy)
	if banner != "" {
		for serviceName, serviceData := range config.ServicePatterns {
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
		if portService, exists := config.PortServiceMapping[fmt.Sprintf("%d", port)]; exists {
			// Apply service aliases
			if alias, hasAlias := config.ServiceAliases[portService]; hasAlias {
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

// performComprehensiveCredentialScan performs credential testing for all discovered hosts
// Technique: Iterates through all hosts and their open ports, testing each service with credential scanner
// Implements parallel processing with worker pools for efficient credential testing
// Returns map of IP addresses to their credential test results
func performComprehensiveCredentialScan(assets []Asset, apiURL string) map[string][]CredentialTest {
	fmt.Println("\n=== Phase 6: Credential Testing ===")
	fmt.Println("Testing default credentials on discovered services...")

	credentialResults := make(map[string][]CredentialTest)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Worker pool for credential testing
	maxWorkers := 10
	semaphore := make(chan struct{}, maxWorkers)

	// Load service detection configuration
	serviceConfig := loadServiceDetectionConfig()

	totalTests := 0
	for _, asset := range assets {
		if len(asset.Ports) > 0 {
			totalTests += len(asset.Ports)
		}
	}

	fmt.Printf("Found %d open ports across %d hosts to test\n", totalTests, len(assets))

	testedCount := 0
	for _, asset := range assets {
		if len(asset.Ports) == 0 {
			continue
		}

		for _, port := range asset.Ports {
			wg.Add(1)
			go func(asset Asset, port PortScanResult) {
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
					serviceDetection = detectServiceWithConfidence(asset.Address, port.Number, banner, serviceConfig)
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

				response, err := performCredentialScan(asset.Address, port.Number, service, apiURL)
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

// ScanHosts orchestrates a comprehensive multi-phase network discovery process.
// Technique: Combines passive discovery, ARP scanning, ICMP pings, TCP/SYN scans, and port scanning.
// Implements parallel processing and progressive scanning techniques for maximum host discovery.
// Exports results to JSON format for further analysis and API consumption.
func ScanHosts(config *Config) {
	// Get network interface based on configuration
	var primary NetworkInfo

	if config.Network.Interface == "auto" && config.Network.AutoDetectLocal {
		// Auto-detect primary interface
		interfaces, err := GetNetworkInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		primary = GetPrimaryNetworkInterface(interfaces)
		fmt.Printf("Auto-detected network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	} else if config.Network.Interface != "auto" {
		// Use specified interface
		interfaces, err := GetNetworkInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Find the specified interface
		found := false
		for _, iface := range interfaces {
			if iface.InterfaceName == config.Network.Interface {
				primary = iface
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("Error: Specified interface '%s' not found\n", config.Network.Interface)
			fmt.Println("Available interfaces:")
			for _, iface := range interfaces {
				fmt.Printf("  - %s (%s)\n", iface.InterfaceName, iface.IPAddress)
			}
			return
		}

		fmt.Printf("Using specified network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	} else {
		// Fallback to auto-detection
		interfaces, err := GetNetworkInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		primary = GetPrimaryNetworkInterface(interfaces)
		fmt.Printf("Using network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	}

	// Initialize host lists
	var allHosts []Host

	// Add network-based hosts if enabled
	if config.Network.ScanLocalNetwork {
		networkHosts, err := GetAllHostsInNetwork(primary.NetworkCIDR)
		if err != nil {
			fmt.Printf("Error getting hosts from network %s: %v\n", primary.NetworkCIDR, err)
		} else {
			allHosts = append(allHosts, networkHosts...)
			fmt.Printf("Added %d hosts from network %s\n", len(networkHosts), primary.NetworkCIDR)
		}
	}

	// Add file-based hosts if enabled
	if config.Network.ScanFileList && config.Files.IPListFile != "" {
		fmt.Printf("Loading hosts from file: %s\n", config.Files.IPListFile)
		fileHosts, err := LoadHostsFromFile(config.Files.IPListFile)
		if err != nil {
			fmt.Printf("Warning: Could not load hosts from %s: %v\n", config.Files.IPListFile, err)
		} else {
			allHosts = append(allHosts, fileHosts...)
			fmt.Printf("Added %d hosts from file %s\n", len(fileHosts), config.Files.IPListFile)
		}
	}

	// Remove duplicates
	hosts := removeDuplicateHosts(allHosts)

	if len(hosts) == 0 {
		fmt.Println("No hosts to scan. Check configuration settings.")
		return
	}

	fmt.Printf("Scanning %d unique hosts total...\n", len(hosts))
	fmt.Println("Starting comprehensive multi-technique scanning for better host discovery...")

	fmt.Println("\n=== Phase 0: Passive Network Discovery ===")

	fmt.Println("Starting mDNS discovery in parallel...")
	var mdnsResults *DiscoveryResult
	var mdnsWg sync.WaitGroup

	mdnsWg.Add(1)
	go func() {
		defer mdnsWg.Done()
		mdnsResults = performMDNSDiscovery()
	}()

	passiveResults, err := performPassiveDiscovery(primary, 20*time.Second)
	if err != nil {
		fmt.Printf("Error during passive discovery: %v - continuing with active scanning\n", err)
	}

	mdnsWg.Wait()

	passiveHostCount := len(passiveResults.Hosts)
	fmt.Printf("Passive discovery found %d hosts\n", passiveHostCount)

	fmt.Println("\n=== Phase 1: ARP Scanning ===")

	var arpResults ArpScanResults

	if !config.ARP.Enabled {
		fmt.Println("ARP scanning is disabled in configuration, skipping...")
		// Create empty results for consistency
		arpResults = ArpScanResults{
			Hosts:    make([]HostStatus, 0),
			Duration: 0,
		}
	} else {
		fmt.Printf("ARP scan configuration: timeout=%s, workers=%d, rate_limit=%s\n",
			config.ARP.Timeout, config.ARP.Workers, config.ARP.RateLimit)

		var err error
		arpResults, err = performARPScan(hosts, primary, config.GetARPTimeout())
		if err != nil {
			fmt.Printf("Error during ARP scan: %v\n", err)
			return
		}
	}

	// Calculate ARP alive count for both enabled/disabled cases
	arpAliveCount := 0
	for _, host := range arpResults.Hosts {
		if host.IsAlive {
			arpAliveCount++
		}
	}

	if config.ARP.Enabled {
		fmt.Printf("\nARP scan found %d alive hosts\n", arpAliveCount)
	}

	fmt.Println("\n=== Phase 2: ICMP Ping Scanning ===")
	pingResults, err := performPingScan(hosts)
	if err != nil {
		fmt.Printf("Error during ICMP scan: %v - continuing with ARP results only\n", err)
	}

	mergedHosts := MergeARPAndPingResults(arpResults, pingResults)

	fmt.Println("\n=== Phase 3: TCP Port Scanning ===")
	tcpScannedHosts := OptionalTCPScan(mergedHosts)

	fmt.Println("\n=== Phase 4: SYN Scanning (Advanced) ===")
	activeScannedHosts, err := performSYNScan(tcpScannedHosts, primary)
	if err != nil {
		fmt.Printf("Error during SYN scan: %v - continuing with previous results\n", err)
		activeScannedHosts = tcpScannedHosts
	}

	finalHosts := MergePassiveAndActiveResults(passiveResults, activeScannedHosts, primary.NetworkCIDR)

	fmt.Println("\n=== Phase 5: Advanced Port Scanning ===")

	var portScanResults map[string][]PortScanResult

	if !config.PortScan.Enabled {
		fmt.Println("Port scanning is disabled in configuration, skipping...")
		portScanResults = make(map[string][]PortScanResult)
	} else {
		fmt.Printf("Port scan configuration: timeout=%s, workers=%d\n",
			config.PortScan.Timeout, config.PortScan.Workers)
		fmt.Println("Performing comprehensive port scanning on discovered hosts...")

		// Get alive hosts for port scanning
		var aliveHosts []HostStatus
		for _, host := range finalHosts {
			if host.IsAlive {
				aliveHosts = append(aliveHosts, host)
			}
		}

		if len(aliveHosts) > 0 {
			// Convert HostStatus to net.IP for PortScanner
			var ips []net.IP
			for _, host := range aliveHosts {
				if ip := net.ParseIP(host.IPAddress); ip != nil {
					ips = append(ips, ip)
				}
			}

			// Perform port scanning
			portResults := PortScanner(ips)

			// Convert PortResult to PortScanResult format
			portScanResults = make(map[string][]PortScanResult)
			for _, result := range portResults {
				if result.State { // Only include open ports
					portScanResult := PortScanResult{
						Number:    result.Port,
						Service:   result.Service,
						Banner:    result.Banner,
						State:     "open",
						Transport: result.Protocol,
					}
					portScanResults[result.IPAddress.String()] = append(portScanResults[result.IPAddress.String()], portScanResult)
				}
			}

			// Display port scanning summary
			totalOpenPorts := 0
			hostsWithOpenPorts := 0
			for _, ports := range portScanResults {
				if len(ports) > 0 {
					hostsWithOpenPorts++
					totalOpenPorts += len(ports)
				}
			}
			fmt.Printf("Port scan completed: Found %d open ports on %d hosts\n", totalOpenPorts, hostsWithOpenPorts)
		} else {
			fmt.Println("No alive hosts found for port scanning")
			portScanResults = make(map[string][]PortScanResult)
		}
	}

	// Credential scanner API URL - can be configured via environment variable
	credentialAPIURL := "http://localhost:8081"
	if envURL := os.Getenv("CREDENTIAL_SCANNER_URL"); envURL != "" {
		credentialAPIURL = envURL
	}

	// Create temporary assets for credential testing
	tempAssets := mergeAllResults(finalHosts, portScanResults, mdnsResults, make(map[string][]CredentialTest))

	// Perform credential testing
	credentialResults := performComprehensiveCredentialScan(tempAssets, credentialAPIURL)

	// Merge all results including credential tests
	finalAssets := mergeAllResults(finalHosts, portScanResults, mdnsResults, credentialResults)

	aliveCount := 0
	for _, host := range finalHosts {
		if host.IsAlive {
			aliveCount++
		}
	}

	fmt.Printf("\n🎯 Final Asset Discovery Results:\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Multi-technique scan completed\n")
	fmt.Printf("Found %d alive hosts out of %d total hosts\n\n", aliveCount, len(finalHosts))

	if len(finalAssets) > 0 {
		fmt.Printf("📋 Asset Inventory Summary:\n")
		fmt.Printf("============================\n")

		deviceTypes := make(map[string]int)
		hostsWithNames := 0
		totalPorts := 0
		totalVulnerableCredentials := 0
		hostsWithVulnerabilities := 0

		for _, asset := range finalAssets {
			deviceTypes[asset.Type]++
			if asset.Hostname != "unknown" {
				hostsWithNames++
			}
			totalPorts += len(asset.Ports)

			// Count credential vulnerabilities
			for _, credTest := range asset.CredTest {
				if credTest.Success {
					totalVulnerableCredentials++
				}
			}
			if len(asset.CredTest) > 0 {
				hasVulnerability := false
				for _, credTest := range asset.CredTest {
					if credTest.Success {
						hasVulnerability = true
						break
					}
				}
				if hasVulnerability {
					hostsWithVulnerabilities++
				}
			}
		}

		fmt.Printf("Total Assets: %d\n", len(finalAssets))
		fmt.Printf("Resolved Hostnames: %d\n", hostsWithNames)
		fmt.Printf("Total Open Ports: %d\n", totalPorts)
		fmt.Printf("Vulnerable Credentials: %d\n", totalVulnerableCredentials)
		fmt.Printf("Hosts with Vulnerabilities: %d\n", hostsWithVulnerabilities)
		fmt.Println("\nDevice Types:")
		for deviceType, count := range deviceTypes {
			fmt.Printf("  %s: %d\n", deviceType, count)
		}

		fmt.Printf("\n📱 Sample Assets (first 5):\n")
		fmt.Printf("============================\n")
		for i, asset := range finalAssets {
			if i >= 5 {
				break
			}
			fmt.Printf("Asset %d:\n", i+1)
			fmt.Printf("  IP: %s\n", asset.Address)
			fmt.Printf("  Hostname: %s\n", asset.Hostname)
			fmt.Printf("  Type: %s\n", asset.Type)
			fmt.Printf("  OS: %s\n", asset.OS)
			fmt.Printf("  Hardware: %s\n", asset.Hardware)
			fmt.Printf("  MAC Vendor: %s\n", asset.MacVendor)
			fmt.Printf("  Open Ports: %d\n", len(asset.Ports))
			if len(asset.Ports) > 0 {
				fmt.Printf("  Services: ")
				for j, port := range asset.Ports {
					if j < 3 { // Show first 3 services
						fmt.Printf("%s(%d) ", port.Service, port.Number)
					}
				}
				if len(asset.Ports) > 3 {
					fmt.Printf("...")
				}
				fmt.Println()
			}

			// Show credential vulnerabilities
			if len(asset.CredTest) > 0 {
				vulnerableCount := 0
				for _, credTest := range asset.CredTest {
					if credTest.Success {
						vulnerableCount++
					}
				}
				if vulnerableCount > 0 {
					fmt.Printf("  ⚠️  Vulnerable Credentials: %d\n", vulnerableCount)
					for _, credTest := range asset.CredTest {
						if credTest.Success {
							fmt.Printf("    - %s:%s (%s)\n", credTest.Username, credTest.Password, credTest.Service)
						}
					}
				}
			}
			fmt.Println()
		}

		if len(finalAssets) > 5 {
			fmt.Printf("... and %d more assets\n", len(finalAssets)-5)
		}

		err := exportAssetsToJSON(finalAssets, config)
		if err != nil {
			fmt.Printf("Error exporting to JSON: %v\n", err)
		}
	}

	fmt.Printf("Passive discovery: %d hosts\n", passiveHostCount)
	fmt.Printf("ARP scan: %d hosts\n", arpAliveCount)

	pingAliveCount := 0
	for _, host := range pingResults.Hosts {
		if host.IsAlive {
			pingAliveCount++
		}
	}
	fmt.Printf("ICMP scan: %d hosts\n", pingAliveCount)

	tcpAliveCount := 0
	for _, host := range tcpScannedHosts {
		if host.IsAlive {
			tcpAliveCount++
		}
	}

	tcpOnlyCount := tcpAliveCount - arpAliveCount - pingAliveCount
	if tcpOnlyCount < 0 {
		tcpOnlyCount = 0
	}
	fmt.Printf("TCP scan: %d additional hosts\n", tcpOnlyCount)

	activeCount := 0
	for _, host := range activeScannedHosts {
		if host.IsAlive {
			activeCount++
		}
	}

	synOnlyCount := activeCount - tcpAliveCount
	if synOnlyCount < 0 {
		synOnlyCount = 0
	}
	fmt.Printf("SYN scan: %d additional hosts\n", synOnlyCount)

	passiveOnlyCount := aliveCount - activeCount
	if passiveOnlyCount < 0 {
		passiveOnlyCount = 0
	}
	fmt.Printf("Unique passive-only hosts: %d\n\n", passiveOnlyCount)

	fmt.Printf("%-15s %-17s %-10s\n", "IP Address", "MAC Address", "Status")
	fmt.Printf("%-15s %-17s %-10s\n", "---------------", "-----------------", "----------")

	sort.Slice(finalHosts, func(i, j int) bool {
		ipA := net.ParseIP(finalHosts[i].IPAddress).To4()
		ipB := net.ParseIP(finalHosts[j].IPAddress).To4()

		if ipA == nil || ipB == nil {
			return finalHosts[i].IPAddress < finalHosts[j].IPAddress
		}

		ipAInt := (uint32(ipA[0]) << 24) | (uint32(ipA[1]) << 16) | (uint32(ipA[2]) << 8) | uint32(ipA[3])
		ipBInt := (uint32(ipB[0]) << 24) | (uint32(ipB[1]) << 16) | (uint32(ipB[2]) << 8) | uint32(ipB[3])

		return ipAInt < ipBInt
	})

	for _, host := range finalHosts {
		if host.IsAlive {
			fmt.Printf("%-15s %-17s %-10s\n", host.IPAddress, host.MACAddress, "Alive")
		}
	}

	fmt.Println("\nShow dead hosts? (y/n):")
	var input string
	fmt.Scanln(&input)

	if strings.ToLower(input) == "y" {
		for _, host := range finalHosts {
			if !host.IsAlive {
				fmt.Printf("%-15s %-17s %-10s\n", host.IPAddress, host.MACAddress, "Dead")
			}
		}
	}
}

// performAdvancedPortScanning function has been removed due to functionality issues.
// Port scanning functionality is now disabled and will be replaced with custom implementation.

// performMDNSDiscovery executes multicast DNS discovery to resolve hostnames and services.
// Technique: Uses mDNS protocol to discover devices that advertise their hostnames and services.
// Implements parallel discovery with configurable timeout and concurrency for efficient scanning.
// Returns DiscoveryResult containing hostname mappings and service information.
func performMDNSDiscovery() *DiscoveryResult {
	fmt.Println("Starting mDNS discovery for hostname resolution...")
	fmt.Println("This will help identify device names and services")

	originalOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(originalOutput)

	discovery := NewMDNSDiscovery()
	discovery.SetTimeout(8 * time.Second)
	discovery.SetMaxConcurrency(8)

	result, err := discovery.Discover()
	if err != nil {
		fmt.Printf("mDNS discovery error: %v\n", err)
		return &DiscoveryResult{
			Services:     make([]ServiceInfo, 0),
			Hosts:        make([]HostInfo, 0),
			ServiceTypes: make(map[string]int),
			Timestamp:    time.Now(),
		}
	}

	fmt.Printf("mDNS discovery completed: found %d hosts with hostnames\n", len(result.Hosts))
	fmt.Printf("Discovered %d services across %d service types\n", len(result.Services), len(result.ServiceTypes))

	if len(result.Hosts) > 0 {
		fmt.Println("Discovered hostnames:")
		for _, host := range result.Hosts {
			if len(host.IPv4) > 0 {
				fmt.Printf("  Host: %s, IPs: %v, Services: %v\n",
					host.Hostname, host.IPv4, host.Services)
			}
		}
	} else {
		fmt.Println("No mDNS hostnames discovered - devices may not support mDNS or network may be filtered")
	}

	return result
}

// mergeAllResults consolidates host discovery, port scanning, mDNS results, and credential tests into comprehensive asset inventory.
// Technique: Creates unified asset records by mapping hostnames from mDNS, port data from scanning, MAC addresses, and credential vulnerabilities.
// Implements asset classification with default values for custom function integration.
// Returns array of Asset structures ready for JSON export and API consumption.
func mergeAllResults(hosts []HostStatus, portResults map[string][]PortScanResult, mdnsResults *DiscoveryResult, credentialResults map[string][]CredentialTest) []Asset {
	var assets []Asset

	fmt.Printf("\n🔗 Asset Management Integration\n")
	fmt.Printf("Creating asset inventory with mDNS hostname mapping...\n")

	hostnameMap := make(map[string]string)

	for _, host := range mdnsResults.Hosts {
		for _, ipv4 := range host.IPv4 {
			hostnameMap[ipv4] = host.Hostname
		}
	}

	fmt.Printf("Found hostname mappings for %d IP addresses\n", len(hostnameMap))

	var macAddresses []string
	for _, host := range hosts {
		if host.IsAlive && host.MACAddress != "" && host.MACAddress != "unknown" {
			macAddresses = append(macAddresses, host.MACAddress)
		}
	}

	fmt.Printf("Skipping MAC vendor lookup for %d devices (will be handled by custom functions)...\n", len(macAddresses))

	for _, host := range hosts {
		if !host.IsAlive {
			continue
		}

		asset := Asset{
			Address:  host.IPAddress,
			Mac:      host.MACAddress,
			Date:     time.Now(),
			Ports:    []PortScanResult{},
			CredTest: []CredentialTest{},
		}

		if hostname, found := hostnameMap[host.IPAddress]; found {
			asset.Hostname = hostname
		} else {
			asset.Hostname = "unknown"
		}

		if ports, found := portResults[host.IPAddress]; found {
			asset.Ports = ports
		}

		// Add credential test results
		if credTests, found := credentialResults[host.IPAddress]; found {
			asset.CredTest = credTests
		}

		asset.MacVendor = "unknown"
		asset.Type = "unknown"
		asset.OS = "unknown"
		asset.Hardware = "unknown"

		assets = append(assets, asset)
	}

	fmt.Printf("Created %d assets with hostname information\n", len(assets))

	hostsWithNames := 0
	for _, asset := range assets {
		if asset.Hostname != "unknown" {
			hostsWithNames++
		}
	}
	fmt.Printf("Successfully resolved hostnames for %d out of %d hosts\n", hostsWithNames, len(assets))

	return assets
}

// exportAssetsToJSON serializes asset inventory to JSON format for external consumption.
// Technique: Marshals asset array to indented JSON and writes to configured output file.
// Implements error handling for file operations and provides export statistics.
// Returns error if JSON marshaling or file writing fails.
func exportAssetsToJSON(assets []Asset, config *Config) error {
	outputFile := config.Files.OutputFile
	if outputFile == "" {
		outputFile = "assets.json" // Default fallback
	}

	fmt.Printf("\n💾 Exporting assets to %s...\n", outputFile)

	jsonData, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assets to JSON: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", outputFile, err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", outputFile, err)
	}

	fmt.Printf("Successfully exported %d assets to %s\n", len(assets), outputFile)
	fmt.Printf("File size: %d bytes\n", len(jsonData))

	return nil
}
