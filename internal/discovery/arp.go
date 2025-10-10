package discovery

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"redmantis/internal/network"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ScanARP performs comprehensive ARP scanning to discover live hosts on the network.
// Technique: Uses raw packet capture with gopacket library to send ARP requests and capture responses.
// Implements batch processing with retry logic and progressive timeouts for thorough discovery.
// Returns ArpScanResults containing all discovered hosts with their MAC addresses.
func ScanARP(hosts []network.Host, iface network.NetworkInfo, timeout time.Duration) (ArpScanResults, error) {
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
		results = make(map[string]network.HostStatus)
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
			results[ip] = network.HostStatus{
				IPAddress:  ip,
				MACAddress: mac,
				IsAlive:    true,
			}
			mu.Unlock()
		}
	}()

	for _, host := range hosts {
		results[host.IPAddress] = network.HostStatus{
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
			go func(host network.Host) {
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
		var nonRespondingHosts []network.Host
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
				go func(host network.Host) {
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

	var hostStatuses []network.HostStatus
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
func LoadHostsFromFile(filename string) ([]network.Host, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var hosts []network.Host
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
				hosts = append(hosts, network.Host{IPAddress: line})
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
func expandCIDR(cidr string) ([]network.Host, error) {
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

	var hosts []network.Host

	// Handle special cases
	if ones >= 31 {
		// /31 and /32 networks - use all addresses
		hosts = append(hosts, network.Host{IPAddress: ipNet.IP.String()})
		if ones == 31 {
			// For /31, add the other address too
			nextIP := make(net.IP, len(ipNet.IP))
			copy(nextIP, ipNet.IP)
			nextIP[3]++
			hosts = append(hosts, network.Host{IPAddress: nextIP.String()})
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
		hosts = append(hosts, network.Host{IPAddress: hostIP.String()})
	}

	return hosts, nil
}

// removeDuplicateHosts removes duplicate hosts based on IP address
func removeDuplicateHosts(hosts []network.Host) []network.Host {
	seen := make(map[string]bool)
	var unique []network.Host

	for _, host := range hosts {
		if !seen[host.IPAddress] {
			seen[host.IPAddress] = true
			unique = append(unique, host)
		}
	}

	return unique
}

// MergeHosts combines host lists and removes duplicates
func MergeHosts(hostLists ...[]network.Host) []network.Host {
	var allHosts []network.Host
	for _, hosts := range hostLists {
		allHosts = append(allHosts, hosts...)
	}
	return removeDuplicateHosts(allHosts)
}
