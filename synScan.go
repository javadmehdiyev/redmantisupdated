package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SynScanResults represents the results of a SYN scan
type SynScanResults struct {
	Hosts    []HostStatus
	Duration time.Duration
}

// performSYNScan performs a SYN scan on critical ports to find hosts that didn't respond to other scans
// This is more stealthy and can sometimes bypass firewalls
func performSYNScan(hosts []HostStatus, iface NetworkInfo) ([]HostStatus, error) {
	scanStart := time.Now()
	defer func() {
		fmt.Printf("SYN scan duration: %.2f seconds\n", time.Since(scanStart).Seconds())
	}()

	// Only scan hosts that haven't been identified as alive yet
	var deadHosts []Host
	for _, host := range hosts {
		if !host.IsAlive {
			deadHosts = append(deadHosts, Host{IPAddress: host.IPAddress})
		}
	}

	if len(deadHosts) == 0 {
		return hosts, nil
	}

	fmt.Printf("Performing SYN scan on %d non-responding hosts...\n", len(deadHosts))

	// Critical ports for SYN scanning
	criticalPorts := []int{80, 443, 22, 23}

	// Open the device for capturing
	handle, err := pcap.OpenLive(iface.InterfaceName, 65536, true, 5*time.Second)
	if err != nil {
		return hosts, fmt.Errorf("failed to open device %s for SYN scan: %w", iface.InterfaceName, err)
	}
	defer handle.Close()

	// Set BPF filter to only capture TCP packets
	err = handle.SetBPFFilter("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack")
	if err != nil {
		return hosts, fmt.Errorf("failed to set BPF filter for SYN scan: %w", err)
	}

	// Get the interface hardware address (MAC)
	ifaceObj, err := net.InterfaceByName(iface.InterfaceName)
	if err != nil {
		return hosts, fmt.Errorf("failed to get interface %s: %w", iface.InterfaceName, err)
	}
	srcMAC := ifaceObj.HardwareAddr

	// Parse the source IP address
	srcIP := net.ParseIP(iface.IPAddress).To4()
	if srcIP == nil {
		return hosts, fmt.Errorf("failed to parse source IP %s", iface.IPAddress)
	}

	// Create a map to store results
	var (
		discoveredHosts = make(map[string]bool)
		mu              sync.Mutex
	)

	// Start the packet capture goroutine
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

	// Process captured packets
	go func() {
		for packet := range packetsChan {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)

			if tcpLayer == nil || ipLayer == nil {
				continue
			}

			tcp, _ := tcpLayer.(*layers.TCP)
			ip, _ := ipLayer.(*layers.IPv4)

			// Look for SYN-ACK responses (flags == 18)
			if tcp.SYN && tcp.ACK {
				srcIPStr := ip.SrcIP.String()

				mu.Lock()
				discoveredHosts[srcIPStr] = true
				mu.Unlock()
			}
		}
	}()

	// Function to send a SYN packet to a host
	sendSYNPacket := func(hostIP string, port layers.TCPPort) error {
		dstIP := net.ParseIP(hostIP).To4()
		if dstIP == nil {
			return fmt.Errorf("failed to parse destination IP %s", hostIP)
		}

		// Get gateway MAC address through ARP
		gatewayMAC, err := getGatewayMAC(handle, srcMAC, srcIP, dstIP)
		if err != nil {
			// Use broadcast as fallback
			gatewayMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		}

		// Create the ethernet layer
		eth := layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       gatewayMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// Create the IP layer
		ip := layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}

		// Create the TCP layer
		tcp := layers.TCP{
			SrcPort: layers.TCPPort(54321), // Random source port
			DstPort: port,
			SYN:     true, // Set SYN flag
			Window:  14600,
			Seq:     1000, // Random sequence number
		}

		// Set up TCP layer
		tcp.SetNetworkLayerForChecksum(&ip)

		// Serialize the packet
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err = gopacket.SerializeLayers(buffer, opts, &eth, &ip, &tcp)
		if err != nil {
			return fmt.Errorf("failed to serialize SYN packet: %w", err)
		}

		// Send the packet
		return handle.WritePacketData(buffer.Bytes())
	}

	fmt.Println("Sending SYN packets to critical ports...")

	// Send SYN packets to all hosts and critical ports
	for _, host := range deadHosts {
		for _, port := range criticalPorts {
			// Try to send a SYN packet
			err := sendSYNPacket(host.IPAddress, layers.TCPPort(port))
			if err != nil {
				// Just log and continue
				fmt.Printf("Warning: Failed to send SYN packet to %s:%d: %v\n",
					host.IPAddress, port, err)
			}

			// Add a short delay between packets
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Wait for responses
	fmt.Println("Waiting for SYN-ACK responses...")
	time.Sleep(5 * time.Second)

	// Stop the packet capture
	close(stopChan)

	// Update hosts that responded to SYN scan
	for i, host := range hosts {
		if discoveredHosts[host.IPAddress] {
			hosts[i].IsAlive = true
		}
	}

	// Count newly discovered hosts
	newlyDiscovered := 0
	for ip := range discoveredHosts {
		found := false
		for _, host := range hosts {
			if host.IPAddress == ip && host.IsAlive {
				found = true
				break
			}
		}
		if !found {
			newlyDiscovered++
		}
	}

	fmt.Printf("SYN scan completed: Found %d additional hosts\n", newlyDiscovered)

	return hosts, nil
}

// getGatewayMAC tries to get the MAC address of the gateway for the given destination IP
func getGatewayMAC(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) (net.HardwareAddr, error) {
	// This is a simplified implementation - in a real-world application,
	// you would use the routing table to determine the gateway
	// For now, we'll just use a broadcast MAC
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
}
