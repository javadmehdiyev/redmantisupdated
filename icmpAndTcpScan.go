package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PingScanResults represents the results of a ping scan
type PingScanResults struct {
	Hosts    []HostStatus
	Duration time.Duration
}

// performPingScan uses ICMP ping to scan for alive hosts
func performPingScan(hosts []Host) (PingScanResults, error) {
	start := time.Now()

	// Create a map to store results
	var (
		results = make(map[string]HostStatus)
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Pre-populate the results map with all hosts as "dead"
	for _, host := range hosts {
		results[host.IPAddress] = HostStatus{
			IPAddress:  host.IPAddress,
			MACAddress: "unknown",
			IsAlive:    false,
		}
	}

	// Determine the ping command based on the OS
	pingCmd := "ping"
	pingArgs := []string{}

	switch runtime.GOOS {
	case "windows":
		pingArgs = []string{"-n", "1", "-w", "1000"}
	case "darwin": // macOS
		pingArgs = []string{"-c", "1", "-W", "1"}
	default: // Linux and others
		pingArgs = []string{"-c", "1", "-W", "1"}
	}

	// Function to ping a host
	pingHost := func(host Host) {
		defer wg.Done()

		args := append(pingArgs, host.IPAddress)
		cmd := exec.Command(pingCmd, args...)

		if err := cmd.Run(); err == nil {
			// If ping succeeds, mark the host as alive
			mu.Lock()
			status := results[host.IPAddress]
			status.IsAlive = true
			results[host.IPAddress] = status
			mu.Unlock()
		}
	}

	// Use a semaphore to limit concurrent pings
	maxConcurrent := 50
	sem := make(chan struct{}, maxConcurrent)

	fmt.Println("Starting ICMP ping scan...")

	// Ping all hosts
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{} // Acquire

		go func(h Host) {
			defer func() { <-sem }() // Release
			pingHost(h)
		}(host)
	}

	// Wait for all ping operations to complete
	wg.Wait()

	// Convert results map to slice
	var hostStatuses []HostStatus
	aliveCount := 0

	for _, status := range results {
		hostStatuses = append(hostStatuses, status)
		if status.IsAlive {
			aliveCount++
		}
	}

	fmt.Printf("ICMP scan completed: Found %d alive hosts\n", aliveCount)

	return PingScanResults{
		Hosts:    hostStatuses,
		Duration: time.Since(start),
	}, nil
}

// MergeARPAndPingResults combines results from ARP and ping scans
func MergeARPAndPingResults(arpResults ArpScanResults, pingResults PingScanResults) []HostStatus {
	// Create a map to store the merged results
	mergedMap := make(map[string]HostStatus)

	// Add all ARP results to the map
	for _, host := range arpResults.Hosts {
		mergedMap[host.IPAddress] = host
	}

	// Update or add ping results
	for _, host := range pingResults.Hosts {
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
	var mergedResults []HostStatus
	for _, host := range mergedMap {
		mergedResults = append(mergedResults, host)
	}

	return mergedResults
}

// OptionalTCPScan performs a quick TCP port scan on common ports for hosts that didn't respond to ARP or ICMP
func OptionalTCPScan(hosts []HostStatus) []HostStatus {
	// Most common ports that are likely to be open on various systems
	commonPorts := []int{
		// Web services
		80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
		// Remote access
		22, 23, 3389, 5900, 5901,
		// File sharing
		445, 139, 21, 2049,
		// Database
		1433, 3306, 5432, 6379, 27017,
		// Other common services
		25, 53, 110, 143, 993, 995, 1723, 5060, 5061,
		// IoT and home devices
		554, 1883, 5683, 8883,
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		updated = make(map[string]bool)
	)

	// Find hosts that are marked as dead
	var deadHosts []HostStatus
	for _, host := range hosts {
		if !host.IsAlive {
			deadHosts = append(deadHosts, host)
		}
	}

	if len(deadHosts) == 0 {
		return hosts
	}

	fmt.Printf("Performing extended TCP port scan on %d non-responding hosts...\n", len(deadHosts))
	fmt.Printf("This may take a few minutes. Scanning %d common ports per host.\n", len(commonPorts))

	// Limit concurrent connections but increase from previous value
	maxConcurrent := 200
	sem := make(chan struct{}, maxConcurrent)

	// Timeout settings - shorter for faster scanning
	shortTimeout := 300 * time.Millisecond

	// Use a ticker to show progress
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			mu.Lock()
			discoveredCount := len(updated)
			mu.Unlock()
			if discoveredCount > 0 {
				fmt.Printf("TCP scan in progress: found %d additional hosts so far...\n", discoveredCount)
			}
		}
	}()

	// For each dead host, scan all ports concurrently
	for _, host := range deadHosts {
		for _, port := range commonPorts {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(h HostStatus, p int) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				// Handle IPv4 and IPv6 addresses properly
				var address string
				if strings.Contains(h.IPAddress, ":") {
					// IPv6 address
					address = fmt.Sprintf("[%s]:%d", h.IPAddress, p)
				} else {
					// IPv4 address
					address = fmt.Sprintf("%s:%d", h.IPAddress, p)
				}

				// Use shorter timeout for faster scanning
				conn, err := net.DialTimeout("tcp", address, shortTimeout)

				if err == nil {
					// Port is open, mark the host as alive
					conn.Close()
					mu.Lock()
					if !updated[h.IPAddress] {
						updated[h.IPAddress] = true
					}
					mu.Unlock()
				}
			}(host, port)
		}
	}

	wg.Wait()
	ticker.Stop()

	// Create the updated host list
	aliveCount := 0
	for i, host := range hosts {
		if updated[host.IPAddress] {
			hosts[i].IsAlive = true
			aliveCount++
		}
	}

	fmt.Printf("TCP scan completed: Found %d additional hosts\n", aliveCount)

	return hosts
}
