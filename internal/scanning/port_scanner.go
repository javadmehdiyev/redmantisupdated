package scanning

import (
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"redmantis/internal/assets"
)

// Common ports to scan (both TCP and UDP - nmap will differentiate)
var CommonPorts = []int{
	21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137, 139, 161, 177, 389, 427, 443, 445, 465, 500, 515, 520, 523, 548, 623, 626, 636, 873, 902, 1080, 1099, 1433, 1434, 1521, 1604, 1645, 1701, 1883, 1900, 2049, 2181, 2375, 2379, 2425, 3128, 3306, 3389, 4730, 5060, 5222, 5351, 5353, 5432, 5555, 5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8080, 8081, 8443, 8545, 8686, 9000, 9001, 9042, 9092, 9100, 9200, 9418, 9999, 11211, 27017, 33848, 37777, 50000, 50070, 61616, 5000, 7000,
}

// NmapXMLResult represents the XML structure returned by nmap
type NmapXMLResult struct {
	XMLName xml.Name `xml:"nmaprun"`
	Host    struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortId   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					Extrainfo string `xml:"extrainfo,attr"`
				} `xml:"service"`
				Script []struct {
					Id     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
		Os struct {
			OsMatch []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
			} `xml:"osmatch"`
		} `xml:"os"`
	} `xml:"host"`
}

// ScanPorts performs port scanning on a specific IP address
func ScanPorts(ipAddress string, portList []int) []assets.PortResult {
	var results []assets.PortResult

	// Convert port list to string format for nmap
	portStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(portList)), ","), "[]")

	// Build nmap command with XML output
	cmd := exec.Command("nmap",
		"-sS",                // SYN scan
		"-sV",                // Version detection
		"-O",                 // OS detection
		"-T4",                // Aggressive timing (faster)
		"--min-rate", "1000", // Minimum packet rate
		"-p", portStr, // Port list
		"-oX", "-", // XML output to stdout
		ipAddress)

	// Execute nmap command
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error running nmap: %v\n", err)
		return results
	}

	// Parse XML output
	var nmapResult NmapXMLResult
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		fmt.Printf("Error parsing nmap XML: %v\n", err)
		return results
	}

	// Note: OS information is available in nmapResult.Host.Os.OsMatch if needed in the future

	// Process each port
	for _, port := range nmapResult.Host.Ports.Port {
		portNum, err := strconv.Atoi(port.PortId)
		if err != nil {
			continue
		}

		// Determine if port is open
		isOpen := port.State.State == "open"

		// Build service name
		service := port.Service.Name
		if port.Service.Product != "" {
			service = port.Service.Product
			if port.Service.Version != "" {
				service += " " + port.Service.Version
			}
		}

		// Build banner from service info and scripts
		var banner strings.Builder
		if port.Service.Product != "" {
			banner.WriteString(port.Service.Product)
			if port.Service.Version != "" {
				banner.WriteString(" " + port.Service.Version)
			}
			if port.Service.Extrainfo != "" {
				banner.WriteString(" " + port.Service.Extrainfo)
			}
		}

		// Add script output to banner
		for _, script := range port.Script {
			if script.Output != "" {
				if banner.Len() > 0 {
					banner.WriteString(" | ")
				}
				banner.WriteString(script.Output)
			}
		}

		result := assets.PortResult{
			Port:      portNum,
			State:     isOpen,
			Service:   service,
			Banner:    banner.String(),
			Protocol:  port.Protocol,
			IPAddress: ipAddress,
		}

		results = append(results, result)
	}

	return results
}

// ScanMultiple scans multiple IP addresses using the common port list
func ScanMultiple(ips []net.IP) []assets.PortResult {
	var allResults []assets.PortResult

	for _, ip := range ips {
		results := ScanPorts(ip.String(), CommonPorts)
		allResults = append(allResults, results...)
	}

	return allResults
}
