package discovery

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"redmantis/internal/assets"
	"redmantis/internal/config"
	"redmantis/internal/credentials"
	"redmantis/internal/network"
	"redmantis/internal/scanning"
	"redmantis/internal/screenshot"
)

// Orchestrator coordinates all scanning activities
type Orchestrator struct {
	config   *config.Config
	assetMgr *assets.Manager
}

// NewOrchestrator creates a new scanning orchestrator
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	return &Orchestrator{
		config:   cfg,
		assetMgr: assets.NewManager(),
	}
}

// identifyNetBIOSHosts filters hosts to only include those with NetBIOS/SMB ports open
func (o *Orchestrator) identifyNetBIOSHosts(hosts []network.HostStatus, portResults map[string][]assets.PortScanResult) []network.HostStatus {
	var netbiosHosts []network.HostStatus

	// NetBIOS/SMB related ports
	netbiosPorts := map[int]bool{
		137: true, // NetBIOS Name Service (UDP)
		138: true, // NetBIOS Datagram Service (UDP)
		139: true, // NetBIOS Session Service (TCP)
		445: true, // SMB over TCP
	}

	for _, host := range hosts {
		if !host.IsAlive {
			continue
		}

		// Check if this host has any NetBIOS/SMB ports open
		if ports, found := portResults[host.IPAddress]; found {
			hasNetBIOSPort := false

			for _, port := range ports {
				if port.State == "open" && netbiosPorts[port.Number] {
					hasNetBIOSPort = true
					fmt.Printf("Found NetBIOS/SMB port %d open on %s\n", port.Number, host.IPAddress)
					break
				}
			}

			if hasNetBIOSPort {
				netbiosHosts = append(netbiosHosts, host)
			}
		}
	}

	return netbiosHosts
}

// Run executes the comprehensive multi-phase network discovery process.
// Technique: Combines passive discovery, ARP scanning, ICMP pings, TCP/SYN scans, and port scanning.
// Implements parallel processing and progressive scanning techniques for maximum host discovery.
// Exports results to JSON format for further analysis and API consumption.
func (o *Orchestrator) Run() {
	// Print header
	fmt.Println("RedMantis v2 - Network Scanner")
	fmt.Println("==============================")
	fmt.Println()

	fmt.Printf("Loaded configuration for: %s\n", o.config.Service.Name)
	fmt.Printf("Network interface mode: %s\n", o.config.Network.Interface)
	if o.config.Network.AutoDetectLocal {
		fmt.Println("Auto-detecting local network configuration...")
	}
	fmt.Println()

	// Get network interface based on configuration
	var primary network.NetworkInfo

	if o.config.Network.Interface == "auto" && o.config.Network.AutoDetectLocal {
		// Auto-detect primary interface
		interfaces, err := network.GetInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		primary = network.GetPrimary(interfaces)
		fmt.Printf("Auto-detected network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	} else if o.config.Network.Interface != "auto" {
		// Use specified interface
		interfaces, err := network.GetInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Find the specified interface
		found := false
		for _, iface := range interfaces {
			if iface.InterfaceName == o.config.Network.Interface {
				primary = iface
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("Error: Specified interface '%s' not found\n", o.config.Network.Interface)
			fmt.Println("Available interfaces:")
			for _, iface := range interfaces {
				fmt.Printf("  - %s (%s)\n", iface.InterfaceName, iface.IPAddress)
			}
			return
		}

		fmt.Printf("Using specified network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	} else {
		// Fallback to auto-detection
		interfaces, err := network.GetInterfaces()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		primary = network.GetPrimary(interfaces)
		fmt.Printf("Using network interface: %s (%s)\n", primary.InterfaceName, primary.IPAddress)
	}

	// Initialize host lists
	var allHosts []network.Host

	// Add network-based hosts if enabled
	if o.config.Network.ScanLocalNetwork {
		networkHosts, err := network.GetNetworkHosts(primary.NetworkCIDR)
		if err != nil {
			fmt.Printf("Error getting hosts from network %s: %v\n", primary.NetworkCIDR, err)
		} else {
			allHosts = append(allHosts, networkHosts...)
			fmt.Printf("Added %d hosts from network %s\n", len(networkHosts), primary.NetworkCIDR)
		}
	}

	// Add file-based hosts if enabled
	if o.config.Network.ScanFileList && o.config.Files.IPListFile != "" {
		fmt.Printf("Loading hosts from file: %s\n", o.config.Files.IPListFile)
		fileHosts, err := LoadHostsFromFile(o.config.Files.IPListFile)
		if err != nil {
			fmt.Printf("Warning: Could not load hosts from %s: %v\n", o.config.Files.IPListFile, err)
		} else {
			allHosts = append(allHosts, fileHosts...)
			fmt.Printf("Added %d hosts from file %s\n", len(fileHosts), o.config.Files.IPListFile)
		}
	}

	// Remove duplicates
	hosts := MergeHosts(allHosts)

	if len(hosts) == 0 {
		fmt.Println("No hosts to scan. Check configuration settings.")
		return
	}

	fmt.Printf("Scanning %d unique hosts total...\n", len(hosts))
	fmt.Println("Starting comprehensive multi-technique scanning for better host discovery...")

	fmt.Println("\n=== Phase 0: Passive Network Discovery ===")

	// mDNS discovery (configurable)
	var mdnsResults *DiscoveryResult
	var mdnsWg sync.WaitGroup

	if o.config.MDNS.Enabled {
		fmt.Printf("mDNS configuration: timeout=%s, retries=%d, concurrency=%d\n",
			o.config.MDNS.Timeout, o.config.MDNS.Retries, o.config.MDNS.Concurrency)

		mdnsWg.Add(1)
		go func() {
			defer mdnsWg.Done()
			mdnsResults = ScanMDNS()
		}()
	} else {
		fmt.Println("mDNS discovery is disabled in configuration, skipping...")
		mdnsResults = &DiscoveryResult{
			Services:     make([]ServiceInfo, 0),
			Hosts:        make([]HostInfo, 0),
			ServiceTypes: make(map[string]int),
			Timestamp:    time.Now(),
		}
	}

	passiveResults, err := ScanPassive(primary, 20*time.Second)
	if err != nil {
		fmt.Printf("Error during passive discovery: %v - continuing with active scanning\n", err)
	}

	if o.config.MDNS.Enabled {
		mdnsWg.Wait()
	}

	passiveHostCount := len(passiveResults.Hosts)
	mdnsHostCount := len(mdnsResults.Hosts)
	fmt.Printf("Passive discovery found %d hosts\n", passiveHostCount)
	fmt.Printf("mDNS discovery found %d hosts with hostnames\n", mdnsHostCount)

	fmt.Println("\n=== Phase 1: ARP Scanning ===")

	var arpResults ArpScanResults

	if !o.config.ARP.Enabled {
		fmt.Println("ARP scanning is disabled in configuration, skipping...")
		// Create empty results for consistency
		arpResults = ArpScanResults{
			Hosts:    make([]network.HostStatus, 0),
			Duration: 0,
		}
	} else {
		fmt.Printf("ARP scan configuration: timeout=%s, workers=%d, rate_limit=%s\n",
			o.config.ARP.Timeout, o.config.ARP.Workers, o.config.ARP.RateLimit)

		var err error
		arpResults, err = ScanARP(hosts, primary, o.config.GetARPTimeout())
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

	if o.config.ARP.Enabled {
		fmt.Printf("\nARP scan found %d alive hosts\n", arpAliveCount)
	}

	fmt.Println("\n=== Phase 2: ICMP Ping Scanning ===")
	pingResults, err := ScanPing(hosts)
	if err != nil {
		fmt.Printf("Error during ICMP scan: %v - continuing with ARP results only\n", err)
	}

	mergedHosts := o.assetMgr.MergeARPAndPingResults(arpResults.Hosts, pingResults.Hosts)

	fmt.Println("\n=== Phase 3: TCP Port Scanning ===")
	tcpScannedHosts := ScanTCP(mergedHosts)

	fmt.Println("\n=== Phase 4: SYN Scanning (Advanced) ===")
	activeScannedHosts, err := ScanSYN(tcpScannedHosts, primary)
	if err != nil {
		fmt.Printf("Error during SYN scan: %v - continuing with previous results\n", err)
		activeScannedHosts = tcpScannedHosts
	}

	finalHosts := o.assetMgr.MergePassiveAndActiveResults(passiveResults.Hosts, activeScannedHosts, primary.NetworkCIDR)

	fmt.Println("\n=== Phase 5: Advanced Port Scanning ===")

	var portScanResults map[string][]assets.PortScanResult

	if !o.config.PortScan.Enabled {
		fmt.Println("Port scanning is disabled in configuration, skipping...")
		portScanResults = make(map[string][]assets.PortScanResult)
	} else {
		fmt.Printf("Port scan configuration: timeout=%s, workers=%d\n",
			o.config.PortScan.Timeout, o.config.PortScan.Workers)
		fmt.Println("Performing comprehensive port scanning on discovered hosts...")

		// Get alive hosts for port scanning
		var aliveHosts []network.HostStatus
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

			// Perform port scanning with config timeout and workers
			portResults := scanning.ScanMultiple(ips, o.config.GetPortScanTimeout(), o.config.PortScan.Workers)

			// Convert PortResult to PortScanResult format
			portScanResults = make(map[string][]assets.PortScanResult)
			for _, result := range portResults {
				if result.State { // Only include open ports
					portScanResult := assets.PortScanResult{
						Number:    result.Port,
						Service:   result.Service,
						Banner:    result.Banner,
						State:     "open",
						Transport: result.Protocol,
					}
					portScanResults[result.IPAddress] = append(portScanResults[result.IPAddress], portScanResult)
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
			portScanResults = make(map[string][]assets.PortScanResult)
		}
	}

	fmt.Println("\n=== Phase 6: NetBIOS Discovery ===")

	var netbiosResults NetBIOSResults

	if !o.config.NetBIOS.Enabled {
		fmt.Println("NetBIOS scanning is disabled in configuration, skipping...")
		netbiosResults = NetBIOSResults{
			Hosts:    make(map[string]NetBIOSInfo),
			Duration: 0,
		}
	} else {
		fmt.Printf("NetBIOS scan configuration: timeout=%s, workers=%d\n",
			o.config.NetBIOS.Timeout, o.config.NetBIOS.Workers)

		// First identify hosts with NetBIOS/SMB ports open
		netbiosHosts := o.identifyNetBIOSHosts(finalHosts, portScanResults)

		if len(netbiosHosts) > 0 {
			fmt.Printf("Found %d hosts with NetBIOS/SMB ports open, scanning for Windows info...\n", len(netbiosHosts))
			netbiosResults = ScanNetBIOS(netbiosHosts)
		} else {
			fmt.Println("No hosts found with NetBIOS/SMB ports open")
			netbiosResults = NetBIOSResults{
				Hosts:    make(map[string]NetBIOSInfo),
				Duration: 0,
			}
		}
	}

	// Count Windows hosts discovered
	windowsCount := 0
	hostnameCount := 0
	for _, info := range netbiosResults.Hosts {
		if info.Available {
			if strings.Contains(strings.ToLower(info.OSInfo), "windows") {
				windowsCount++
			}
			if info.Hostname != "" {
				hostnameCount++
			}
		}
	}

	if windowsCount > 0 {
		fmt.Printf("NetBIOS Discovery Summary: Found %d Windows hosts with %d hostnames\n", windowsCount, hostnameCount)
	}

	// Create hostname mapping from mDNS results
	hostnameMap := make(map[string]string)
	for _, host := range mdnsResults.Hosts {
		for _, ipv4 := range host.IPv4 {
			hostnameMap[ipv4] = host.Hostname
		}
	}

	// Create NetBIOS maps for asset merging
	netbiosHostnames := make(map[string]string)
	netbiosOSInfo := make(map[string]string)
	for ip, info := range netbiosResults.Hosts {
		if info.Available {
			if info.Hostname != "" {
				netbiosHostnames[ip] = info.Hostname
			}
			if info.OSInfo != "" {
				netbiosOSInfo[ip] = info.OSInfo
			}
		}
	}

	// Create temporary assets for credential testing (with NetBIOS info)
	tempAssets := o.assetMgr.MergeAllResults(finalHosts, portScanResults, hostnameMap, netbiosHostnames, netbiosOSInfo, make(map[string][]assets.CredentialTest))

	// Perform credential testing with new native Go tester
	var credentialResults map[string][]assets.CredentialTest

	if o.config.Credentials.Enabled {
		credTester, err := credentials.NewTester(o.config)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize credential tester: %v\n", err)
			fmt.Println("Skipping credential testing...")
			credentialResults = make(map[string][]assets.CredentialTest)
		} else {
			credentialResults = credTester.TestAllAssets(tempAssets)
		}
	} else {
		fmt.Println("\n=== Phase 8: Credential Testing ===")
		fmt.Println("Credential testing is disabled in configuration, skipping...")
		credentialResults = make(map[string][]assets.CredentialTest)
	}

	// Merge all results including credential tests (with NetBIOS info)
	finalAssets := o.assetMgr.MergeAllResults(finalHosts, portScanResults, hostnameMap, netbiosHostnames, netbiosOSInfo, credentialResults)

	// Phase 7: Screenshot Capture for Web Services
	fmt.Println("\n=== Phase 7: Screenshot Capture ===")
	screenshotService := screenshot.NewService(15*time.Second, 5) // 15s timeout, 5 concurrent workers
	finalAssets = screenshotService.CaptureScreenshots(finalAssets)

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
		o.printAssetSummary(finalAssets)

		err := assets.ExportToJSON(finalAssets, o.config)
		if err != nil {
			fmt.Printf("Error exporting to JSON: %v\n", err)
		}
	}

	o.printScanSummary(passiveHostCount, arpAliveCount, pingResults, tcpScannedHosts, activeScannedHosts, aliveCount, finalHosts)
}

func (o *Orchestrator) printAssetSummary(finalAssets []assets.Asset) {
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
						fmt.Printf("    - %s:%s (%s:%d)\n", credTest.Username, credTest.Password, credTest.Service, credTest.Port)
					}
				}
			}
		}
		fmt.Println()
	}

	if len(finalAssets) > 5 {
		fmt.Printf("... and %d more assets\n", len(finalAssets)-5)
	}
}

func (o *Orchestrator) printScanSummary(passiveHostCount, arpAliveCount int, pingResults PingScanResults, tcpScannedHosts, activeScannedHosts []network.HostStatus, aliveCount int, finalHosts []network.HostStatus) {
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
