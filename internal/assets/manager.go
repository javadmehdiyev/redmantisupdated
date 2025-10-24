package assets

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"redmantis/internal/network"
)

// Manager handles asset data merging and management
type Manager struct {
	mu sync.RWMutex
}

// NewManager creates a new asset manager
func NewManager() *Manager {
	return &Manager{}
}

// MergeAllResults consolidates host discovery, port scanning, mDNS results, NetBIOS results, and credential tests into comprehensive asset inventory.
// This is a simple version without mDNS dependency to avoid circular imports
func (m *Manager) MergeAllResults(hosts []network.HostStatus, portResults map[string][]PortScanResult, hostnameMap map[string]string, netbiosHostnames map[string]string, netbiosOSInfo map[string]string, credentialResults map[string][]CredentialTest) []Asset {
	m.mu.Lock()
	defer m.mu.Unlock()

	var assets []Asset

	fmt.Printf("\n🔗 Asset Management Integration\n")
	fmt.Printf("Creating asset inventory with hostname mapping...\n")

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

		// First check NetBIOS hostname (more reliable for Windows)
		if netbiosHostname, found := netbiosHostnames[host.IPAddress]; found && netbiosHostname != "" {
			asset.Hostname = netbiosHostname
		} else if hostname, found := hostnameMap[host.IPAddress]; found {
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

		// Enrich asset with intelligent detection
		// MAC Vendor Lookup
		asset.MacVendor = LookupMACVendor(asset.Mac)

		// OS Detection (uses NetBIOS, banners, ports, hostname, MAC vendor)
		netbiosOSValue := ""
		if osInfo, found := netbiosOSInfo[host.IPAddress]; found {
			netbiosOSValue = osInfo
		}
		asset.OS = DetectOS(asset.Ports, netbiosOSValue, asset.Hostname, asset.MacVendor)

		// Device Type Classification (uses ports, services, MAC vendor)
		asset.Type = ClassifyDeviceType(asset.Ports, asset.MacVendor)

		// Hardware Detection (uses MAC vendor, device type, OS, services)
		asset.Hardware = DetectHardware(asset.MacVendor, asset.Type, asset.OS, asset.Ports)

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

// MergeARPAndPingResults combines results from ARP and ping scans
func (m *Manager) MergeARPAndPingResults(arpResults, pingResults []network.HostStatus) []network.HostStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create a map to store the merged results
	mergedMap := make(map[string]network.HostStatus)

	// Add all ARP results to the map
	for _, host := range arpResults {
		mergedMap[host.IPAddress] = host
	}

	// Update or add ping results
	for _, host := range pingResults {
		if host.IsAlive {
			// If the host is alive in ping results
			if existing, found := mergedMap[host.IPAddress]; found {
				// If the host is already in the map but not marked as alive, mark it alive
				if !existing.IsAlive {
					existing.IsAlive = true
					// Keep the MAC address if it was found in ARP scan
					mergedMap[host.IPAddress] = existing
				}
			} else {
				// If the host is not in the map, add it
				mergedMap[host.IPAddress] = host
			}
		}
	}

	// Convert map back to slice
	var mergedResults []network.HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}

// MergePassiveAndActiveResults combines passive discovery results with active scan results
// It filters passive results to only include hosts from the local network
func (m *Manager) MergePassiveAndActiveResults(passiveResults map[string]network.HostStatus, activeHosts []network.HostStatus, networkCIDR string) []network.HostStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse the CIDR to get network information
	_, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		fmt.Printf("Warning: Failed to parse network CIDR %s: %v\n", networkCIDR, err)
		// If we can't parse the CIDR, fall back to the isInLocalNetwork function
		// but only include hosts that are in the local network
		return m.mergeWithLocalNetworkFilter(passiveResults, activeHosts)
	}

	// Convert passive results to a map for easy lookup
	passiveMap := passiveResults

	// Create a new map to store merged results
	mergedMap := make(map[string]network.HostStatus)

	// Add all active scan results
	for _, host := range activeHosts {
		mergedMap[host.IPAddress] = host
	}

	// Add or update with passive results, but only if they're in the specified network
	for ip, passiveHost := range passiveMap {
		// Parse the IP address
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			continue // Skip invalid IPs
		}

		// Only include IPv4 addresses in our target network
		if ipAddr.To4() != nil && ipNet.Contains(ipAddr) {
			if existingHost, found := mergedMap[ip]; found {
				// If host exists from active scan but MAC is unknown, use the passive MAC
				if existingHost.MACAddress == "unknown" && passiveHost.MACAddress != "unknown" {
					existingHost.MACAddress = passiveHost.MACAddress
					mergedMap[ip] = existingHost
				}
			} else {
				// If host was only found in passive scan, add it
				mergedMap[ip] = passiveHost
			}
		} else if strings.HasPrefix(ip, "fe80::") {
			// For IPv6, only include link-local addresses
			if existingHost, found := mergedMap[ip]; found {
				if existingHost.MACAddress == "unknown" && passiveHost.MACAddress != "unknown" {
					existingHost.MACAddress = passiveHost.MACAddress
					mergedMap[ip] = existingHost
				}
			} else {
				mergedMap[ip] = passiveHost
			}
		}
	}

	// Convert map back to slice
	var mergedResults []network.HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}

// mergeWithLocalNetworkFilter is a fallback function that uses the isInLocalNetwork function
// to filter passive results
func (m *Manager) mergeWithLocalNetworkFilter(passiveResults map[string]network.HostStatus, activeHosts []network.HostStatus) []network.HostStatus {
	passiveMap := passiveResults
	mergedMap := make(map[string]network.HostStatus)

	// Add all active scan results
	for _, host := range activeHosts {
		mergedMap[host.IPAddress] = host
	}

	// Add or update with passive results, but only if they're in the local network
	for ip, passiveHost := range passiveMap {
		if isInLocalNetwork(ip) {
			if existingHost, found := mergedMap[ip]; found {
				if existingHost.MACAddress == "unknown" && passiveHost.MACAddress != "unknown" {
					existingHost.MACAddress = passiveHost.MACAddress
					mergedMap[ip] = existingHost
				}
			} else {
				mergedMap[ip] = passiveHost
			}
		}
	}

	// Convert map back to slice
	var mergedResults []network.HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}

// isInLocalNetwork checks if an IP address is in the local network
// This function filters out public IP addresses from passive discovery
func isInLocalNetwork(ipStr string) bool {
	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// If it's an IPv6 address, only include link-local (fe80::) addresses
	if ip.To4() == nil {
		return strings.HasPrefix(ipStr, "fe80::")
	}

	// For IPv4, check common private network ranges
	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}

	// 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}

	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}

	// 169.254.0.0/16 (link-local)
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}

	// For our specific case, we know we're in a 10.23.x.x network
	// This should be adjusted based on the actual network being scanned
	if ip[0] == 10 && ip[1] == 23 {
		return true
	}

	// Exclude all other IPs (public addresses, etc.)
	return false
}
