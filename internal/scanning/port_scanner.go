package scanning

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"redmantis/internal/assets"
)

var CommonPorts = getDeduplicatedPorts()

func getDeduplicatedPorts() []int {
	// Load JSON config
	data, err := os.ReadFile("../config.json")
	if err != nil {
		return nil
	}

	var cfg struct {
		Range    string `json:"range"`
		PortList []int  `json:"port_list"`
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}

	// Map to deduplicate
	portMap := make(map[int]bool)
	var uniquePorts []int

	if cfg.Range != "" {
		parts := strings.Split(cfg.Range, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(parts[1]))

			if start > 0 && end <= 65535 && end >= start {
				for p := start; p <= end; p++ {
					if !portMap[p] {
						portMap[p] = true
						uniquePorts = append(uniquePorts, p)
					}
				}
			}
		}
	}

	// Add ports from port_list
	for _, port := range cfg.PortList {
		if port > 0 && port <= 65535 && !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	// Sort before returning
	sort.Ints(uniquePorts)
	return uniquePorts
}

// ScanPorts performs fast native Go port scanning on a specific IP address
// Uses TCP connect scanning with parallel workers for speed and reliability
func ScanPorts(ipAddress string, portList []int, timeout time.Duration, workers int) []assets.PortResult {
	scanner := NewPortScanner(timeout, workers)
	return scanner.ScanHost(ipAddress, portList)
}

// ScanMultiple scans multiple IP addresses using the common port list with parallel execution
func ScanMultiple(ips []net.IP, timeout time.Duration, workers int) []assets.PortResult {
	var allResults []assets.PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	total := len(ips)

	// Scan each host in parallel (limited concurrency to avoid overwhelming network)
	hostSemaphore := make(chan struct{}, 5) // Max 5 hosts scanned concurrently

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, ipAddr net.IP) {
			defer wg.Done()

			// Acquire host semaphore
			hostSemaphore <- struct{}{}
			defer func() { <-hostSemaphore }()

			fmt.Printf("  [%d/%d] Scanning %s...\n", index+1, total, ipAddr.String())

			// Scan this host
			results := ScanPorts(ipAddr.String(), CommonPorts, timeout, workers)

			// Append results
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()

			if len(results) > 0 {
				fmt.Printf("  [%d/%d] Found %d open ports on %s\n",
					index+1, total, len(results), ipAddr.String())
			}
		}(i, ip)
	}

	wg.Wait()
	return allResults
}
