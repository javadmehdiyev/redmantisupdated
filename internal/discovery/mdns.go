package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
)

// MDNSDiscovery handles mDNS discovery operations with retry support
type MDNSDiscovery struct {
	timeout        time.Duration
	maxConcurrency int
	retries        int
	retryDelay     time.Duration
	serviceTypes   []string
}

// NewMDNSDiscovery creates a new MDNSDiscovery instance with comprehensive service types
func NewMDNSDiscovery() *MDNSDiscovery {
	return &MDNSDiscovery{
		timeout:        12 * time.Second, // Increased for better discovery
		maxConcurrency: 10,               // More concurrent queries
		retries:        3,                // Retry failed/incomplete queries
		retryDelay:     2 * time.Second,  // Delay between retries
		serviceTypes:   getComprehensiveServiceTypes(),
	}
}

// getComprehensiveServiceTypes returns an extensive list of mDNS service types
func getComprehensiveServiceTypes() []string {
	return []string{
		// Web Services
		"_http._tcp",
		"_https._tcp",
		"_http-alt._tcp",
		"_web._tcp",

		// Remote Access
		"_ssh._tcp",
		"_sftp-ssh._tcp",
		"_ftp._tcp",
		"_telnet._tcp",
		"_rdp._tcp",
		"_vnc._tcp",
		"_rfb._tcp",

		// File Sharing
		"_smb._tcp",
		"_afp._tcp",
		"_afpovertcp._tcp",
		"_nfs._tcp",
		"_adisk._tcp",
		"_webdav._tcp",

		// Printing
		"_printer._tcp",
		"_ipp._tcp",
		"_ipps._tcp",
		"_pdl-datastream._tcp",
		"_ptp._tcp",

		// Apple Services
		"_airplay._tcp",
		"_raop._tcp",
		"_airport._tcp",
		"_apple-tv._tcp",
		"_homekit._tcp",
		"_hap._tcp",
		"_companion-link._tcp",
		"_home-sharing._tcp",
		"_appletv-v2._tcp",
		"_airprint._tcp",
		"_airdrop._tcp",
		"_sleep-proxy._udp",

		// Media & Streaming
		"_spotify-connect._tcp",
		"_googlecast._tcp",
		"_chromecast._tcp",
		"_daap._tcp",
		"_dpap._tcp",
		"_roku._tcp",
		"_soundtouch._tcp",
		"_sonos._tcp",

		// Smart Home & IoT
		"_mqtt._tcp",
		"_coap._udp",
		"_hue._tcp",
		"_philips-hue._tcp",
		"_smartthings._tcp",
		"_homeassistant._tcp",
		"_esphomelib._tcp",
		"_matter._tcp",
		"_thread._tcp",

		// Network Services
		"_workstation._tcp",
		"_device-info._tcp",
		"_services._dns-sd._udp",
		"_domain._udp",
		"_snmp._udp",

		// Databases
		"_mysql._tcp",
		"_postgresql._tcp",
		"_mongodb._tcp",
		"_redis._tcp",
		"_elasticsearch._tcp",

		// Development
		"_git._tcp",
		"_svn._tcp",
		"_jenkins._tcp",
		"_docker._tcp",

		// Gaming
		"_minecraft._tcp",
		"_steam._tcp",

		// Other Common Services
		"_ldap._tcp",
		"_kerberos._tcp",
		"_ntp._udp",
		"_dns-update._tcp",
		"_sftp._tcp",
		"_upnp._tcp",
	}
}

// SetTimeout sets the discovery timeout
func (md *MDNSDiscovery) SetTimeout(timeout time.Duration) {
	md.timeout = timeout
}

// SetMaxConcurrency sets maximum concurrent service discoveries
func (md *MDNSDiscovery) SetMaxConcurrency(max int) {
	md.maxConcurrency = max
}

// AddServiceType adds a custom service type to discover
func (md *MDNSDiscovery) AddServiceType(serviceType string) {
	md.serviceTypes = append(md.serviceTypes, serviceType)
}

// SetServiceTypes replaces the default service types
func (md *MDNSDiscovery) SetServiceTypes(serviceTypes []string) {
	md.serviceTypes = serviceTypes
}

// Discover performs comprehensive mDNS discovery with retries for maximum accuracy
func (md *MDNSDiscovery) Discover() (*DiscoveryResult, error) {
	startTime := time.Now()

	result := &DiscoveryResult{
		Services:     make([]ServiceInfo, 0),
		Hosts:        make([]HostInfo, 0),
		ServiceTypes: make(map[string]int),
		Timestamp:    startTime,
		metadata:     make(map[string][]net.IP),
	}

	fmt.Printf("Starting comprehensive mDNS discovery with %d retries...\n", md.retries)
	fmt.Printf("Scanning %d service types with timeout=%v\n", len(md.serviceTypes), md.timeout)

	// Track services found in each attempt
	var attemptResults []*DiscoveryResult

	// Perform multiple discovery attempts with retries
	for attempt := 1; attempt <= md.retries; attempt++ {
		fmt.Printf("  mDNS discovery attempt %d/%d...\n", attempt, md.retries)

		attemptResult := &DiscoveryResult{
			Services:     make([]ServiceInfo, 0),
			Hosts:        make([]HostInfo, 0),
			ServiceTypes: make(map[string]int),
			Timestamp:    time.Now(),
			metadata:     make(map[string][]net.IP),
		}

		var wg sync.WaitGroup
		semaphore := make(chan struct{}, md.maxConcurrency)

		// Discover each service type in parallel
		for _, serviceType := range md.serviceTypes {
			wg.Add(1)
			go func(st string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				md.discoverServiceWithRetry(st, attemptResult, attempt)
			}(serviceType)
		}

		wg.Wait()
		attemptResults = append(attemptResults, attemptResult)

		// Wait before next retry (except on last attempt)
		if attempt < md.retries {
			time.Sleep(md.retryDelay)
		}
	}

	// Merge all attempts (deduplicating)
	md.mergeAttempts(attemptResults, result)

	result.Duration = time.Since(startTime)

	// Process and finalize results
	md.processResults(result)

	return result, nil
}

// discoverServiceWithRetry discovers a specific service type with enhanced error handling
func (md *MDNSDiscovery) discoverServiceWithRetry(serviceType string, result *DiscoveryResult, attemptNum int) {
	entriesCh := make(chan *mdns.ServiceEntry, 200) // Increased buffer

	ctx, cancel := context.WithTimeout(context.Background(), md.timeout)
	defer cancel()

	params := &mdns.QueryParam{
		Service:             serviceType,
		Domain:              "local",
		Timeout:             md.timeout,
		Entries:             entriesCh,
		WantUnicastResponse: true, // Request unicast responses for better reliability
	}

	// Launch query in goroutine
	queryDone := make(chan error, 1)
	go func() {
		defer close(entriesCh)
		err := mdns.Query(params)
		queryDone <- err
	}()

	// Collect entries
	entryCount := 0
	for {
		select {
		case entry, ok := <-entriesCh:
			if !ok {
				// Channel closed, query complete
				return
			}

			if entry != nil {
				md.addServiceEntry(entry, serviceType, result)
				entryCount++
			}

		case err := <-queryDone:
			// Query completed (successfully or with error)
			if err != nil {
				// Only log errors on first attempt to reduce noise
				if attemptNum == 1 {
					log.Printf("Query error for %s (attempt %d): %v", serviceType, attemptNum, err)
				}
			}
			// Drain any remaining entries
			for entry := range entriesCh {
				if entry != nil {
					md.addServiceEntry(entry, serviceType, result)
					entryCount++
				}
			}
			return

		case <-ctx.Done():
			// Timeout reached
			return
		}
	}
}

// mergeAttempts combines results from multiple discovery attempts, deduplicating entries
func (md *MDNSDiscovery) mergeAttempts(attempts []*DiscoveryResult, finalResult *DiscoveryResult) {
	// Track unique services by composite key
	uniqueServices := make(map[string]ServiceInfo)
	uniqueHosts := make(map[string][]net.IP)

	for attemptIdx, attempt := range attempts {
		for _, service := range attempt.Services {
			// Create unique key for service
			key := fmt.Sprintf("%s|%s|%d", service.Hostname, service.ServiceType, service.Port)

			// Keep first occurrence or merge IPs
			if existing, found := uniqueServices[key]; found {
				// Merge IPv4 addresses
				existing.IPv4 = mergeUnique(existing.IPv4, service.IPv4)
				existing.IPv6 = mergeUnique(existing.IPv6, service.IPv6)
				uniqueServices[key] = existing
			} else {
				uniqueServices[key] = service
			}
		}

		// Merge metadata
		for hostname, ips := range attempt.metadata {
			uniqueHosts[hostname] = append(uniqueHosts[hostname], ips...)
		}

		// Track which attempt found services
		if len(attempt.Services) > 0 && attemptIdx > 0 {
			fmt.Printf("    Attempt %d found %d additional service entries\n",
				attemptIdx+1, len(attempt.Services))
		}
	}

	// Convert unique services to slice
	for _, service := range uniqueServices {
		finalResult.Services = append(finalResult.Services, service)
		finalResult.ServiceTypes[service.ServiceType]++
	}

	// Set merged metadata
	finalResult.metadata = make(map[string][]net.IP)
	for hostname, ips := range uniqueHosts {
		// Deduplicate IPs
		uniqueIPs := make(map[string]net.IP)
		for _, ip := range ips {
			if ip != nil && !ip.IsUnspecified() {
				uniqueIPs[ip.String()] = ip
			}
		}

		var ipList []net.IP
		for _, ip := range uniqueIPs {
			ipList = append(ipList, ip)
		}
		finalResult.metadata[hostname] = ipList
	}

	fmt.Printf("  Total unique services discovered: %d\n", len(finalResult.Services))
	fmt.Printf("  Total unique hosts: %d\n", len(uniqueHosts))
}

// mergeUnique merges two string slices, removing duplicates
func mergeUnique(slice1, slice2 []string) []string {
	unique := make(map[string]bool)
	for _, s := range slice1 {
		unique[s] = true
	}
	for _, s := range slice2 {
		unique[s] = true
	}

	var result []string
	for s := range unique {
		result = append(result, s)
	}
	return result
}

func (md *MDNSDiscovery) addServiceEntry(entry *mdns.ServiceEntry, serviceType string, result *DiscoveryResult) {
	result.mutex.Lock()
	defer result.mutex.Unlock()

	// Separate IPv4 and IPv6 addresses
	var ipv4s, ipv6s []string
	var allIPs []net.IP

	if entry.AddrV4 != nil && !entry.AddrV4.IsUnspecified() {
		ipv4s = append(ipv4s, entry.AddrV4.String())
		allIPs = append(allIPs, entry.AddrV4)
	}

	if entry.AddrV6 != nil && !entry.AddrV6.IsUnspecified() {
		ipv6s = append(ipv6s, entry.AddrV6.String())
		allIPs = append(allIPs, entry.AddrV6)
	}

	service := ServiceInfo{
		ServiceType: serviceType,
		ServiceName: entry.Name,
		Hostname:    entry.Host,
		Port:        entry.Port,
		IPv4:        ipv4s,
		IPv6:        ipv6s,
		TXTRecords:  entry.InfoFields,
		Info:        entry.Info,
	}

	result.Services = append(result.Services, service)
	result.ServiceTypes[serviceType]++

	// Store host metadata
	if entry.Host != "" {
		if result.metadata == nil {
			result.metadata = make(map[string][]net.IP)
		}
		result.metadata[entry.Host] = append(result.metadata[entry.Host], allIPs...)
	}
}

func (md *MDNSDiscovery) processResults(result *DiscoveryResult) {
	result.mutex.Lock()
	defer result.mutex.Unlock()

	// Process hosts
	hostMap := make(map[string]*HostInfo)

	// Group services by hostname
	servicesByHost := make(map[string][]string)
	for _, service := range result.Services {
		if service.Hostname != "" {
			servicesByHost[service.Hostname] = append(servicesByHost[service.Hostname], service.ServiceType)
		}
	}

	// Create host information
	for hostname, ips := range result.metadata {
		if hostname == "" {
			continue
		}

		var ipv4s, ipv6s []string
		uniqueIPv4 := make(map[string]bool)
		uniqueIPv6 := make(map[string]bool)

		for _, ip := range ips {
			if ip == nil || ip.IsUnspecified() {
				continue
			}

			if ip.To4() != nil {
				if !uniqueIPv4[ip.String()] {
					ipv4s = append(ipv4s, ip.String())
					uniqueIPv4[ip.String()] = true
				}
			} else {
				if !uniqueIPv6[ip.String()] {
					ipv6s = append(ipv6s, ip.String())
					uniqueIPv6[ip.String()] = true
				}
			}
		}

		// Deduplicate services
		uniqueServices := make(map[string]bool)
		var services []string
		for _, service := range servicesByHost[hostname] {
			if !uniqueServices[service] {
				services = append(services, service)
				uniqueServices[service] = true
			}
		}
		sort.Strings(services)

		hostMap[hostname] = &HostInfo{
			Hostname: hostname,
			IPv4:     ipv4s,
			IPv6:     ipv6s,
			Services: services,
		}
	}

	// Convert hostMap to slice
	for _, host := range hostMap {
		result.Hosts = append(result.Hosts, *host)
	}

	// Sort hosts by hostname
	sort.Slice(result.Hosts, func(i, j int) bool {
		return result.Hosts[i].Hostname < result.Hosts[j].Hostname
	})

	// Calculate summary
	result.Summary = md.calculateSummary(result)
}

func (md *MDNSDiscovery) calculateSummary(result *DiscoveryResult) DiscoverySummary {
	summary := DiscoverySummary{
		TotalServices:     len(result.Services),
		TotalHosts:        len(result.Hosts),
		TotalServiceTypes: len(result.ServiceTypes),
	}

	// Find most common service
	maxCount := 0
	for serviceType, count := range result.ServiceTypes {
		if count > maxCount {
			maxCount = count
			summary.MostCommonService = serviceType
		}
	}

	// Count IP addresses
	for _, host := range result.Hosts {
		summary.IPv4Count += len(host.IPv4)
		summary.IPv6Count += len(host.IPv6)
	}

	return summary
}

// GetJSON returns the discovery results as JSON
func (dr *DiscoveryResult) GetJSON() ([]byte, error) {
	return json.MarshalIndent(dr, "", "  ")
}

// PrintSummary prints a human-readable summary
func (dr *DiscoveryResult) PrintSummary() {
	fmt.Println("🔍 mDNS Discovery Sonuçları")
	fmt.Println("═══════════════════════════")
	fmt.Printf("📊 Toplam Servis: %d\n", dr.Summary.TotalServices)
	fmt.Printf("🏠 Toplam Host: %d\n", dr.Summary.TotalHosts)
	fmt.Printf("📂 Servis Türü: %d\n", dr.Summary.TotalServiceTypes)
	fmt.Printf("🏆 En Yaygın: %s\n", dr.Summary.MostCommonService)
	fmt.Printf("⏱️  Süre: %v\n", dr.Duration.Round(time.Millisecond))
	fmt.Printf("🌐 IPv4: %d, IPv6: %d\n", dr.Summary.IPv4Count, dr.Summary.IPv6Count)
}

// ScanMDNS executes comprehensive multicast DNS discovery with retries.
// Technique: Uses mDNS protocol with multiple retry attempts to discover all devices
// that advertise their hostnames and services on the local network.
// Implements parallel discovery with configurable timeout, concurrency, and retry logic
// for maximum service detection accuracy.
// Returns DiscoveryResult containing hostname mappings and service information.
func ScanMDNS() *DiscoveryResult {
	fmt.Println("Starting comprehensive mDNS discovery for hostname resolution...")
	fmt.Println("This will help identify device names and services across the network")

	// Suppress verbose mdns library logging
	originalOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(originalOutput)

	// Create discovery with optimized settings
	discovery := NewMDNSDiscovery()
	discovery.SetTimeout(12 * time.Second) // Longer timeout for thorough scanning
	discovery.SetMaxConcurrency(10)        // More concurrent service queries

	startTime := time.Now()
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

	duration := time.Since(startTime)

	// Print comprehensive summary
	fmt.Printf("\nmDNS discovery completed in %v\n", duration.Round(time.Millisecond))
	fmt.Printf("  Found %d unique hosts with hostnames\n", len(result.Hosts))
	fmt.Printf("  Discovered %d services across %d service types\n",
		len(result.Services), len(result.ServiceTypes))

	if len(result.Hosts) > 0 {
		fmt.Println("\nDiscovered mDNS hosts:")
		for i, host := range result.Hosts {
			if i >= 10 {
				fmt.Printf("  ... and %d more hosts\n", len(result.Hosts)-10)
				break
			}
			if len(host.IPv4) > 0 {
				fmt.Printf("  ✓ %s → %v (%d services)\n",
					host.Hostname, host.IPv4, len(host.Services))
			}
		}
	} else {
		fmt.Println("No mDNS hosts discovered - devices may not support mDNS or network may be filtered")
	}

	// Show service type breakdown
	if len(result.ServiceTypes) > 0 {
		fmt.Printf("\nTop service types found:\n")
		type serviceCount struct {
			name  string
			count int
		}
		var topServices []serviceCount
		for name, count := range result.ServiceTypes {
			topServices = append(topServices, serviceCount{name, count})
		}
		// Sort by count
		for i := 0; i < len(topServices)-1; i++ {
			for j := i + 1; j < len(topServices); j++ {
				if topServices[j].count > topServices[i].count {
					topServices[i], topServices[j] = topServices[j], topServices[i]
				}
			}
		}
		// Show top 5
		for i, sc := range topServices {
			if i >= 5 {
				break
			}
			fmt.Printf("  %d. %s (%d instances)\n", i+1, sc.name, sc.count)
		}
	}

	return result
}
