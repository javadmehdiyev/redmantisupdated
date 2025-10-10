package discovery

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"redmantis/internal/network"
)

// ScanPing uses ICMP ping to scan for alive hosts
func ScanPing(hosts []network.Host) (PingScanResults, error) {
	start := time.Now()

	// Create a map to store results
	var (
		results = make(map[string]network.HostStatus)
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Pre-populate the results map with all hosts as "dead"
	for _, host := range hosts {
		results[host.IPAddress] = network.HostStatus{
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
	pingHost := func(host network.Host) {
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

		go func(h network.Host) {
			defer func() { <-sem }() // Release
			pingHost(h)
		}(host)
	}

	// Wait for all ping operations to complete
	wg.Wait()

	// Convert results map to slice
	var hostStatuses []network.HostStatus
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
