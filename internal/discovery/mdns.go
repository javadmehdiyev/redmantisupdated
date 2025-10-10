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

// MDNSDiscovery handles mDNS discovery operations
type MDNSDiscovery struct {
	timeout        time.Duration
	maxConcurrency int
	serviceTypes   []string
}

// NewMDNSDiscovery creates a new MDNSDiscovery instance
func NewMDNSDiscovery() *MDNSDiscovery {
	return &MDNSDiscovery{
		timeout:        8 * time.Second,
		maxConcurrency: 5,
		serviceTypes: []string{
			"_http._tcp",
			"_https._tcp",
			"_ssh._tcp",
			"_ftp._tcp",
			"_printer._tcp",
			"_ipp._tcp",
			"_airplay._tcp",
			"_spotify-connect._tcp",
			"_googlecast._tcp",
			"_chromecast._tcp",
			"_apple-tv._tcp",
			"_smb._tcp",
			"_afp._tcp",
			"_nfs._tcp",
			"_rfb._tcp",
			"_vnc._tcp",
			"_rdp._tcp",
			"_homekit._tcp",
			"_hap._tcp",
			"_mqtt._tcp",
			"_workstation._tcp",
			"_device-info._tcp",
			"_raop._tcp",
			"_airport._tcp",
			"_companion-link._tcp",
			"_sftp-ssh._tcp",
			"_telnet._tcp",
			"_daap._tcp",
			"_adisk._tcp",
			"_afpovertcp._tcp",
		},
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

// Discover performs mDNS discovery and returns structured results
func (md *MDNSDiscovery) Discover() (*DiscoveryResult, error) {
	startTime := time.Now()

	result := &DiscoveryResult{
		Services:     make([]ServiceInfo, 0),
		Hosts:        make([]HostInfo, 0),
		ServiceTypes: make(map[string]int),
		Timestamp:    startTime,
		metadata:     make(map[string][]net.IP),
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, md.maxConcurrency)

	// Discover each service type
	for _, serviceType := range md.serviceTypes {
		wg.Add(1)
		go func(st string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			md.discoverService(st, result)
		}(serviceType)
	}

	wg.Wait()
	result.Duration = time.Since(startTime)

	// Process and finalize results
	md.processResults(result)

	return result, nil
}

func (md *MDNSDiscovery) discoverService(serviceType string, result *DiscoveryResult) {
	entriesCh := make(chan *mdns.ServiceEntry, 100)

	ctx, cancel := context.WithTimeout(context.Background(), md.timeout)
	defer cancel()

	params := &mdns.QueryParam{
		Service: serviceType,
		Domain:  "local",
		Timeout: md.timeout,
		Entries: entriesCh,
	}

	go func() {
		defer close(entriesCh)
		if err := mdns.Query(params); err != nil {
			log.Printf("Query error for %s: %v", serviceType, err)
		}
	}()

	for {
		select {
		case entry, ok := <-entriesCh:
			if !ok {
				return
			}

			if entry != nil {
				md.addServiceEntry(entry, serviceType, result)
			}

		case <-ctx.Done():
			return
		}
	}
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

// ScanMDNS executes multicast DNS discovery to resolve hostnames and services.
// Technique: Uses mDNS protocol to discover devices that advertise their hostnames and services.
// Implements parallel discovery with configurable timeout and concurrency for efficient scanning.
// Returns DiscoveryResult containing hostname mappings and service information.
func ScanMDNS() *DiscoveryResult {
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
