package discovery

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"redmantis/internal/network"
)

// ScanTCP performs a quick TCP port scan on common ports for hosts that didn't respond to ARP or ICMP
func ScanTCP(hosts []network.HostStatus) []network.HostStatus {
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
	var deadHosts []network.HostStatus
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

			go func(h network.HostStatus, p int) {
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
