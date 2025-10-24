package discovery

import (
	"encoding/binary"
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

// NetBIOSNameEntry represents a single NetBIOS name entry
type NetBIOSNameEntry struct {
	Name  string
	Type  byte
	Flags uint16
}

// ScanNetBIOS performs NetBIOS queries on Windows hosts to get hostname and OS info
// Implementation inspired by csploit/daemon NetBIOS scanner
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

			// Query NetBIOS
			netbiosInfo := queryNetBIOS(h.IPAddress)

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

// queryNetBIOS performs NetBIOS Name Service query (similar to csploit implementation)
func queryNetBIOS(ipAddress string) NetBIOSInfo {
	info := NetBIOSInfo{
		IPAddress: ipAddress,
		Available: false,
	}

	// Create UDP connection to port 137 (NetBIOS Name Service)
	conn, err := net.DialTimeout("udp", ipAddress+":137", 5*time.Second)
	if err != nil {
		return info
	}
	defer conn.Close()

	// Set read deadline
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send NetBIOS query (csploit-style)
	query := buildNetBIOSQuery()
	_, err = conn.Write(query)
	if err != nil {
		return info
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return info
	}

	// Parse response
	if n > 56 {
		entries := parseNetBIOSResponse(buffer[:n])
		if len(entries) > 0 {
			info = extractInfoFromEntries(entries, ipAddress)
		}
	}

	return info
}

// buildNetBIOSQuery creates a NetBIOS NBSTAT query packet
// Based on csploit NetBIOS implementation approach
func buildNetBIOSQuery() []byte {
	query := make([]byte, 50)
	pos := 0

	// Transaction ID
	binary.BigEndian.PutUint16(query[pos:], 0xABCD)
	pos += 2

	// Flags (0x0000 for query)
	binary.BigEndian.PutUint16(query[pos:], 0x0000)
	pos += 2

	// Questions
	binary.BigEndian.PutUint16(query[pos:], 0x0001)
	pos += 2

	// Answer RRs
	binary.BigEndian.PutUint16(query[pos:], 0x0000)
	pos += 2

	// Authority RRs
	binary.BigEndian.PutUint16(query[pos:], 0x0000)
	pos += 2

	// Additional RRs
	binary.BigEndian.PutUint16(query[pos:], 0x0000)
	pos += 2

	// Name length (32 bytes encoded + 1 length byte)
	query[pos] = 0x20
	pos++

	// Encoded NetBIOS name "*" (wildcard)
	// NetBIOS encoding: each half-byte becomes (value + 'A')
	// '*' = 0x2A = 0010 1010 -> "CK"
	// Pad with spaces (0x20 = 0010 0000 -> "CA")
	encodedName := []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	copy(query[pos:], encodedName)
	pos += 32

	// Null terminator
	query[pos] = 0x00
	pos++

	// Type: NBSTAT (0x0021)
	binary.BigEndian.PutUint16(query[pos:], 0x0021)
	pos += 2

	// Class: IN (0x0001)
	binary.BigEndian.PutUint16(query[pos:], 0x0001)
	pos += 2

	return query[:pos]
}

// parseNetBIOSResponse parses NetBIOS NBSTAT response
func parseNetBIOSResponse(data []byte) []NetBIOSNameEntry {
	var entries []NetBIOSNameEntry

	if len(data) < 57 {
		return entries
	}

	// Verify it's a response (bit 15 of flags should be set)
	if (data[2] & 0x80) == 0 {
		return entries
	}

	// Skip header (12 bytes)
	offset := 12

	// Skip question section
	for offset < len(data) && data[offset] != 0 {
		nameLen := int(data[offset])
		if nameLen == 0 || nameLen > 63 {
			break
		}
		offset += nameLen + 1
	}
	offset++ // null terminator

	// Skip type and class
	offset += 4

	if offset+10 > len(data) {
		return entries
	}

	// Skip answer name (2 bytes - pointer)
	offset += 2

	// Skip type (2), class (2), TTL (4)
	offset += 8

	// Data length
	if offset+2 > len(data) {
		return entries
	}
	offset += 2

	// Number of names
	if offset >= len(data) {
		return entries
	}
	numNames := int(data[offset])
	offset++

	// Parse name entries (18 bytes each)
	for i := 0; i < numNames && offset+18 <= len(data); i++ {
		// Extract name (15 bytes)
		nameBytes := make([]byte, 15)
		copy(nameBytes, data[offset:offset+15])

		// Clean name
		name := cleanNetBIOSName(string(nameBytes))

		// Name type
		nameType := data[offset+15]

		// Flags
		flags := binary.BigEndian.Uint16(data[offset+16 : offset+18])

		if name != "" {
			entries = append(entries, NetBIOSNameEntry{
				Name:  name,
				Type:  nameType,
				Flags: flags,
			})
		}

		offset += 18
	}

	return entries
}

// cleanNetBIOSName cleans and validates a NetBIOS name
func cleanNetBIOSName(name string) string {
	// Trim spaces and null bytes
	name = strings.TrimSpace(name)
	name = strings.TrimRight(name, "\x00")

	// Check if name is printable
	for _, r := range name {
		if r < 32 || r > 126 {
			return ""
		}
	}

	// Filter out special markers
	if strings.HasPrefix(name, "\x01\x02__MSBROWSE__") {
		return ""
	}

	return name
}

// extractInfoFromEntries extracts hostname and OS info from NetBIOS entries
func extractInfoFromEntries(entries []NetBIOSNameEntry, ipAddress string) NetBIOSInfo {
	info := NetBIOSInfo{
		IPAddress: ipAddress,
		Available: true,
		OSInfo:    "Windows",
	}

	for _, entry := range entries {
		isGroup := (entry.Flags & 0x8000) != 0

		switch entry.Type {
		case 0x00: // Workstation/Computer Name or Domain/Workgroup
			if !isGroup {
				// Unique name = Computer name
				if info.Hostname == "" {
					info.Hostname = entry.Name
				}
			} else {
				// Group name = Domain/Workgroup
				if info.Domain == "" {
					info.Domain = entry.Name
				}
			}

		case 0x03: // Messenger Service
			if info.Hostname == "" {
				info.Hostname = entry.Name
			}

		case 0x20: // File Server Service
			if info.Hostname == "" {
				info.Hostname = entry.Name
			}

		case 0x1B: // Domain Master Browser
			if info.Domain == "" {
				info.Domain = entry.Name
			}

		case 0x1D: // Master Browser
			if info.Domain == "" {
				info.Domain = entry.Name
			}

		case 0x1E: // Browser Service Elections
			// This confirms it's a Windows system
			info.OSInfo = "Windows"
		}
	}

	// Determine more specific Windows version if possible
	if info.Hostname != "" {
		info.OSInfo = determineWindowsVersion(entries)
	}

	return info
}

// determineWindowsVersion tries to determine Windows version from NetBIOS entries
func determineWindowsVersion(entries []NetBIOSNameEntry) string {
	hasFileServer := false
	hasMasterBrowser := false
	hasDomainMaster := false

	for _, entry := range entries {
		switch entry.Type {
		case 0x20:
			hasFileServer = true
		case 0x1D:
			hasMasterBrowser = true
		case 0x1B:
			hasDomainMaster = true
		}
	}

	// Basic heuristics
	if hasDomainMaster {
		return "Windows Server"
	} else if hasMasterBrowser && hasFileServer {
		return "Windows"
	}

	return "Windows"
}
