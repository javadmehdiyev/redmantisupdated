package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	Target  string           `json:"target"`
	Service string           `json:"service"`
	Results []CredentialTest `json:"results"`
	Summary struct {
		TotalTests int  `json:"total_tests"`
		Successful int  `json:"successful"`
		Failed     int  `json:"failed"`
		Vulnerable bool `json:"vulnerable"`
	} `json:"summary"`
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

	// Service port mapping for automatic service detection
	servicePorts := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		139:   "smb",
		445:   "smb",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
	}

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

				// Determine service type
				service := port.Service
				if service == "" || service == "unknown" {
					if detectedService, exists := servicePorts[port.Number]; exists {
						service = detectedService
					} else {
						// Try to detect from banner
						banner := strings.ToLower(port.Banner)
						if strings.Contains(banner, "ssh") {
							service = "ssh"
						} else if strings.Contains(banner, "ftp") {
							service = "ftp"
						} else if strings.Contains(banner, "mysql") {
							service = "mysql"
						} else if strings.Contains(banner, "postgresql") {
							service = "postgresql"
						} else if strings.Contains(banner, "microsoft") {
							service = "mssql"
						} else if strings.Contains(banner, "redis") {
							service = "redis"
						} else if strings.Contains(banner, "mongodb") {
							service = "mongodb"
						} else if strings.Contains(banner, "samba") || strings.Contains(banner, "smb") {
							service = "smb"
						} else {
							// Skip unknown services
							return
						}
					}
				}

				// Skip if service is not supported by credential scanner
				supportedServices := []string{"ssh", "ftp", "smb", "redis", "postgresql", "mysql", "mssql", "oracle", "mongodb", "rdp"}
				isSupported := false
				for _, supported := range supportedServices {
					if strings.Contains(strings.ToLower(service), supported) {
						service = supported
						isSupported = true
						break
					}
				}

				if !isSupported {
					return
				}

				fmt.Printf("Testing credentials for %s:%d (%s)...\n", asset.Address, port.Number, service)

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
func ScanHosts() {
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	primary := GetPrimaryNetworkInterface(interfaces)
	fmt.Printf("Using network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)

	hosts, err := GetAllHostsInNetwork(primary.NetworkCIDR)
	if err != nil {
		fmt.Printf("Error getting hosts: %v\n", err)
		return
	}

	fmt.Printf("Scanning %d hosts on network %s...\n", len(hosts), primary.NetworkCIDR)
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
	arpResults, err := performARPScan(hosts, primary, 5*time.Second)
	if err != nil {
		fmt.Printf("Error during ARP scan: %v\n", err)
		return
	}

	arpAliveCount := 0
	for _, host := range arpResults.Hosts {
		if host.IsAlive {
			arpAliveCount++
		}
	}

	fmt.Printf("\nARP scan found %d alive hosts\n", arpAliveCount)

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
	fmt.Println("Performing comprehensive port scanning on discovered hosts...")

	// Get alive hosts for port scanning
	var aliveHosts []HostStatus
	for _, host := range finalHosts {
		if host.IsAlive {
			aliveHosts = append(aliveHosts, host)
		}
	}

	var portScanResults map[string][]PortScanResult
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

		err := exportAssetsToJSON(finalAssets)
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
// Technique: Marshals asset array to indented JSON and writes to results.json file.
// Implements error handling for file operations and provides export statistics.
// Returns error if JSON marshaling or file writing fails.
func exportAssetsToJSON(assets []Asset) error {
	fmt.Println("\n💾 Exporting assets to results.json...")

	jsonData, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assets to JSON: %w", err)
	}

	file, err := os.Create("results.json")
	if err != nil {
		return fmt.Errorf("failed to create results.json: %w", err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write to results.json: %w", err)
	}

	fmt.Printf("Successfully exported %d assets to results.json\n", len(assets))
	fmt.Printf("File size: %d bytes\n", len(jsonData))

	return nil
}
