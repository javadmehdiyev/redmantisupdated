package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PassiveDiscoveryResults represents the results of passive discovery
type PassiveDiscoveryResults struct {
	Hosts    map[string]HostStatus
	Duration time.Duration
}

// performPassiveDiscovery listens for network traffic to identify hosts
// This is completely passive and doesn't generate any traffic
func performPassiveDiscovery(iface NetworkInfo, duration time.Duration) (PassiveDiscoveryResults, error) {
	start := time.Now()

	fmt.Printf("Starting passive network discovery for %.0f seconds...\n", duration.Seconds())
	fmt.Println("Listening for local network traffic without sending any packets")
	fmt.Printf("Only collecting hosts in local network ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)\n")

	// Open the device for capturing
	handle, err := pcap.OpenLive(iface.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return PassiveDiscoveryResults{}, fmt.Errorf("failed to open device %s: %w", iface.InterfaceName, err)
	}
	defer handle.Close()

	// Don't use a BPF filter to capture all types of traffic

	// Create a map to store the discovered hosts
	var (
		discoveredHosts = make(map[string]HostStatus)
		mu              sync.Mutex
		ipCounter       = make(map[string]int)
	)

	// Start the packet capture goroutine
	stopChan := make(chan struct{})
	resultsChan := make(chan PassiveDiscoveryResults)

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				mu.Lock()
				resultsChan <- PassiveDiscoveryResults{
					Hosts:    discoveredHosts,
					Duration: time.Since(start),
				}
				mu.Unlock()
				return

			case <-ticker.C:
				// Periodically report progress
				mu.Lock()
				count := len(discoveredHosts)
				mu.Unlock()
				fmt.Printf("Passive discovery in progress: found %d hosts so far\n", count)

			case packet, ok := <-packetSource.Packets():
				if !ok {
					continue
				}
				// Process each packet to extract IP information
				processPacket(packet, &mu, discoveredHosts, ipCounter, iface.IPAddress)
			}
		}
	}()

	// Wait for the specified duration
	time.Sleep(duration)

	// Stop the packet capture
	close(stopChan)

	// Wait for results
	results := <-resultsChan
	close(resultsChan)

	fmt.Printf("Passive discovery completed: Found %d hosts\n", len(results.Hosts))

	return results, nil
}

// processPacket extracts IP and MAC information from a packet
func processPacket(packet gopacket.Packet, mu *sync.Mutex,
	hosts map[string]HostStatus, ipCounter map[string]int, localIP string) {

	// Extract IP layer information
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// Only process IP addresses other than our own and only if they're in our local network
		if ip.SrcIP.String() != localIP && isInLocalNetwork(ip.SrcIP.String()) {
			srcIP := ip.SrcIP.String()

			mu.Lock()
			// Only count as a host if we've seen it multiple times
			ipCounter[srcIP]++

			if ipCounter[srcIP] >= 3 {
				var macStr string

				// Try to get MAC address from ethernet layer
				ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethernetLayer != nil {
					ethernet, _ := ethernetLayer.(*layers.Ethernet)
					macStr = ethernet.SrcMAC.String()
				} else {
					macStr = "unknown"
				}

				// Save the host
				hosts[srcIP] = HostStatus{
					IPAddress:  srcIP,
					MACAddress: macStr,
					IsAlive:    true,
				}
			}
			mu.Unlock()
		}

		// Also check destination IP if it's not a broadcast and in our local network
		if !ip.DstIP.Equal(net.IPv4bcast) && ip.DstIP.String() != localIP && isInLocalNetwork(ip.DstIP.String()) {
			dstIP := ip.DstIP.String()

			mu.Lock()
			ipCounter[dstIP]++

			if ipCounter[dstIP] >= 2 {
				// For destination, we may not have MAC
				hosts[dstIP] = HostStatus{
					IPAddress:  dstIP,
					MACAddress: "unknown",
					IsAlive:    true,
				}
			}
			mu.Unlock()
		}
	}

	// Also check IPv6, but only for local network addresses
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)

		// Process source IPv6 if it's a local address (fe80:: prefix)
		srcIPv6 := ipv6.SrcIP.String()
		if strings.HasPrefix(srcIPv6, "fe80::") {
			mu.Lock()
			ipCounter[srcIPv6]++

			if ipCounter[srcIPv6] >= 2 {
				var macStr string

				// Try to get MAC address from ethernet layer
				ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
				if ethernetLayer != nil {
					ethernet, _ := ethernetLayer.(*layers.Ethernet)
					macStr = ethernet.SrcMAC.String()
				} else {
					macStr = "unknown"
				}

				// Save the host
				hosts[srcIPv6] = HostStatus{
					IPAddress:  srcIPv6,
					MACAddress: macStr,
					IsAlive:    true,
				}
			}
			mu.Unlock()
		}
	}

	// Process ARP packets too
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)

		srcIP := net.IP(arp.SourceProtAddress).String()

		// Only include if it's in our local network
		if isInLocalNetwork(srcIP) {
			srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()

			mu.Lock()
			// ARP packets are definitive proof of a host
			hosts[srcIP] = HostStatus{
				IPAddress:  srcIP,
				MACAddress: srcMAC,
				IsAlive:    true,
			}
			mu.Unlock()
		}
	}
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

// MergePassiveAndActiveResults combines passive discovery results with active scan results
// It filters passive results to only include hosts from the local network
func MergePassiveAndActiveResults(passiveResults PassiveDiscoveryResults, activeHosts []HostStatus, networkCIDR string) []HostStatus {
	// Parse the CIDR to get network information
	_, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		fmt.Printf("Warning: Failed to parse network CIDR %s: %v\n", networkCIDR, err)
		// If we can't parse the CIDR, fall back to the isInLocalNetwork function
		// but only include hosts that are in the local network
		return mergeWithLocalNetworkFilter(passiveResults, activeHosts)
	}

	// Convert passive results to a map for easy lookup
	passiveMap := passiveResults.Hosts

	// Create a new map to store merged results
	mergedMap := make(map[string]HostStatus)

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
	var mergedResults []HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}

// mergeWithLocalNetworkFilter is a fallback function that uses the isInLocalNetwork function
// to filter passive results
func mergeWithLocalNetworkFilter(passiveResults PassiveDiscoveryResults, activeHosts []HostStatus) []HostStatus {
	passiveMap := passiveResults.Hosts
	mergedMap := make(map[string]HostStatus)

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
	var mergedResults []HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}
