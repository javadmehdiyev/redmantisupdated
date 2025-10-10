package discovery

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"redmantis/internal/network"
)

// NetBIOSInfo represents NetBIOS information discovered from a host
type NetBIOSInfo struct {
	IPAddress string
	Hostname  string
	OSInfo    string
	Domain    string
	Available bool
}

// NetBIOSResults holds the results of NetBIOS scanning
type NetBIOSResults struct {
	Hosts    map[string]NetBIOSInfo
	Duration time.Duration
}

// ScanNetBIOS performs NetBIOS queries on Windows hosts to get hostname and OS info
func ScanNetBIOS(hosts []network.HostStatus) NetBIOSResults {
	start := time.Now()

	fmt.Println("Starting NetBIOS scan for Windows hostname and OS detection...")

	var (
		results = make(map[string]NetBIOSInfo)
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Only scan alive hosts
	var aliveHosts []network.HostStatus
	for _, host := range hosts {
		if host.IsAlive {
			aliveHosts = append(aliveHosts, host)
		}
	}

	if len(aliveHosts) == 0 {
		fmt.Println("No alive hosts found for NetBIOS scanning")
		return NetBIOSResults{
			Hosts:    results,
			Duration: time.Since(start),
		}
	}

	// Limit concurrent NetBIOS queries
	maxConcurrent := 20
	sem := make(chan struct{}, maxConcurrent)

	fmt.Printf("Performing NetBIOS queries on %d hosts...\n", len(aliveHosts))

	for _, host := range aliveHosts {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(h network.HostStatus) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Try NetBIOS name service query (port 137/UDP)
			netbiosInfo := queryNetBIOS(h.IPAddress)

			// If NetBIOS fails, try SMB (port 445/TCP) for additional info
			if !netbiosInfo.Available {
				netbiosInfo = querySMBInfo(h.IPAddress)
			}

			if netbiosInfo.Available {
				mu.Lock()
				results[h.IPAddress] = netbiosInfo
				mu.Unlock()

				fmt.Printf("✓ Found NetBIOS info for %s: %s (%s)\n",
					h.IPAddress, netbiosInfo.Hostname, netbiosInfo.OSInfo)
			}
		}(host)
	}

	wg.Wait()

	fmt.Printf("NetBIOS scan completed: Found info for %d hosts\n", len(results))

	return NetBIOSResults{
		Hosts:    results,
		Duration: time.Since(start),
	}
}

// queryNetBIOS performs NetBIOS Name Service query (NBT-NS) on port 137/UDP
func queryNetBIOS(ipAddress string) NetBIOSInfo {
	info := NetBIOSInfo{
		IPAddress: ipAddress,
		Available: false,
	}

	// Create NetBIOS Name Service query packet
	// This is a simplified implementation of NBT-NS query
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:137", ipAddress), 3*time.Second)
	if err != nil {
		return info
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// NetBIOS Name Query packet for "*" (wildcard query)
	// This requests all NetBIOS names registered on the target
	query := buildNetBIOSQuery()

	_, err = conn.Write(query)
	if err != nil {
		return info
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return info
	}

	// Parse NetBIOS response
	if n > 12 { // Minimum NetBIOS response size
		parsed := parseNetBIOSResponse(buffer[:n])
		if parsed.Hostname != "" {
			info.Hostname = parsed.Hostname
			info.OSInfo = parsed.OSInfo
			info.Domain = parsed.Domain
			info.Available = true
		}
	}

	return info
}

// querySMBInfo tries to get hostname and OS info via SMB (port 445/TCP)
func querySMBInfo(ipAddress string) NetBIOSInfo {
	info := NetBIOSInfo{
		IPAddress: ipAddress,
		Available: false,
	}

	// Try to connect to SMB port 445
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ipAddress), 5*time.Second)
	if err != nil {
		// Also try port 139 (NetBIOS Session Service)
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:139", ipAddress), 5*time.Second)
		if err != nil {
			return info
		}
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Send SMB negotiate request
	negotiatePacket := buildSMBNegotiatePacket()
	_, err = conn.Write(negotiatePacket)
	if err != nil {
		return info
	}

	// Read SMB response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return info
	}

	// Parse SMB response to extract OS information
	if n > 32 { // Minimum SMB response size
		parsed := parseSMBResponse(buffer[:n])
		if parsed.Hostname != "" || parsed.OSInfo != "" {
			info.Hostname = parsed.Hostname
			info.OSInfo = parsed.OSInfo
			info.Available = true
		}
	}

	return info
}

// buildNetBIOSQuery creates a NetBIOS Name Service query packet
func buildNetBIOSQuery() []byte {
	// NetBIOS Name Service Query for "*" (all names)
	// Transaction ID: 0x1234
	// Flags: Standard Query (0x0100)
	// Questions: 1
	// Answer RRs: 0
	// Authority RRs: 0
	// Additional RRs: 0
	// Query: * (wildcard)
	query := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags (Standard query)
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs

		// Query for "*<00>" (Computer name)
		0x20, // Length of encoded name (32 bytes)

		// Encoded NetBIOS name "*" padded to 15 chars + service type
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // "CKAAAAAA"
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // "AAAAAAAA"
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // "AAAAAAAA"
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // "AAAAAAAA"

		0x00,       // Name terminator
		0x00, 0x21, // Type: NB (NetBIOS)
		0x00, 0x01, // Class: IN
	}

	return query
}

// buildSMBNegotiatePacket creates an SMB negotiate protocol request
func buildSMBNegotiatePacket() []byte {
	// SMB1 Protocol Negotiate Request
	// This is a simplified SMB negotiate to trigger OS information disclosure
	packet := []byte{
		// NetBIOS Session Service header
		0x00,             // Message type: Session message
		0x00, 0x00, 0x2F, // Length (47 bytes)

		// SMB Header
		0xFF, 0x53, 0x4D, 0x42, // Protocol identifier "SMB"
		0x72,                   // Command: Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x07, 0xC0, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID
		0x00, 0x00, // UID
		0x00, 0x00, // MID

		// SMB Parameters
		0x00, // Word count

		// SMB Data
		0x0C, 0x00, // Byte count
		0x02,                                                             // Dialect list
		0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // "NT LM 0.12"
	}

	return packet
}

// parseNetBIOSResponse parses NetBIOS Name Service response
func parseNetBIOSResponse(data []byte) NetBIOSInfo {
	info := NetBIOSInfo{}

	if len(data) < 12 {
		return info
	}

	// Check if this is a valid NetBIOS response
	if (data[2] & 0x80) == 0 { // Response flag should be set
		return info
	}

	// Skip to the answer section
	offset := 12

	// Skip the question section by finding the query name
	for offset < len(data) && data[offset] != 0 {
		offset++
	}
	offset += 5 // Skip terminator + type + class

	if offset >= len(data) {
		return info
	}

	// Parse answer records
	for offset+12 < len(data) {
		// Skip name pointer
		if data[offset] >= 0xC0 {
			offset += 2
		} else {
			// Skip full name
			for offset < len(data) && data[offset] != 0 {
				offset++
			}
			offset++
		}

		if offset+10 > len(data) {
			break
		}

		recordType := (int(data[offset]) << 8) | int(data[offset+1])
		dataLen := (int(data[offset+8]) << 8) | int(data[offset+9])
		offset += 10

		if offset+dataLen > len(data) {
			break
		}

		if recordType == 0x0021 { // NB record type
			// Parse NetBIOS names
			for i := 0; i < dataLen; i += 18 {
				if offset+i+18 > len(data) {
					break
				}

				// Extract NetBIOS name (first 15 bytes)
				name := strings.TrimSpace(string(data[offset+i : offset+i+15]))
				nameType := data[offset+i+15]

				// Name type 0x00 = Workstation/Computer name
				// Name type 0x20 = Server service
				if nameType == 0x00 && name != "" && !strings.HasPrefix(name, "__") {
					info.Hostname = name
				}

				// Try to determine OS based on NetBIOS names
				if strings.Contains(name, "MSBROWSE") || nameType == 0x01 {
					info.OSInfo = "Windows"
				}
			}
		}

		offset += dataLen
	}

	// If we found a hostname, assume it's Windows
	if info.Hostname != "" && info.OSInfo == "" {
		info.OSInfo = "Windows"
	}

	return info
}

// parseSMBResponse parses SMB negotiate response for OS information
func parseSMBResponse(data []byte) NetBIOSInfo {
	info := NetBIOSInfo{}

	if len(data) < 36 {
		return info
	}

	// Check SMB signature
	if !(data[4] == 0xFF && data[5] == 0x53 && data[6] == 0x4D && data[7] == 0x42) {
		return info
	}

	// For SMB negotiate response, look for OS and LAN Manager strings
	// These typically appear after the SMB header in the data section

	dataStart := 32 // Skip NetBIOS header + SMB header

	// Look for null-terminated strings that might contain OS info
	for i := dataStart; i < len(data)-10; i++ {
		if data[i] == 0 {
			continue
		}

		// Find the end of this string
		end := i
		for end < len(data) && data[end] != 0 {
			end++
		}

		if end-i > 3 && end-i < 50 {
			str := string(data[i:end])

			// Look for Windows version indicators
			if strings.Contains(strings.ToLower(str), "windows") {
				info.OSInfo = str
				break
			} else if strings.Contains(strings.ToLower(str), "microsoft") {
				info.OSInfo = "Windows"
			} else if strings.Contains(str, "NT") && len(str) < 20 {
				info.OSInfo = "Windows " + str
			}
		}

		i = end
	}

	// If no specific version found but SMB responded, it's likely Windows
	if info.OSInfo == "" {
		info.OSInfo = "Windows"
	}

	return info
}
