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

// Top 50 most common ports for faster scanning
// For full port scan, use nmap's --top-ports option separately
var CommonPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	88,    // Kerberos
	110,   // POP3
	135,   // MSRPC
	139,   // NetBIOS
	143,   // IMAP
	443,   // HTTPS
	445,   // SMB
	993,   // IMAPS
	995,   // POP3S
	1433,  // MSSQL
	3306,  // MySQL
	3389,  // RDP
	5432,  // PostgreSQL
	5900,  // VNC
	6379,  // Redis
	8080,  // HTTP-alt
	8443,  // HTTPS-alt
	27017, // MongoDB
	// Additional common ports
	161,   // SNMP
	389,   // LDAP
	636,   // LDAPS
	1521,  // Oracle
	2049,  // NFS
	5000,  // UPnP
	5353,  // mDNS
	5672,  // AMQP
	7000,  // Cassandra
	8000,  // HTTP-alt
	8081,  // HTTP-alt
	8888,  // HTTP-alt
	9000,  // Various
	9042,  // Cassandra CQL
	9090,  // Prometheus
	9200,  // Elasticsearch
	9300,  // Elasticsearch
	9999,  // Various
	11211, // Memcached
	50000, // SAP
	50070, // Hadoop
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
		"-sS",                   // SYN scan (TCP)
		"-sV",                   // Version detection
		"-T4",                   // Aggressive timing (T5 can be unreliable)
		"--host-timeout", "60s", // Max time per host
		"--max-retries", "1", // Reduce retries for speed
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
	total := len(ips)

	for i, ip := range ips {
		fmt.Printf("  [%d/%d] Scanning %s...\n", i+1, total, ip.String())
		results := ScanPorts(ip.String(), CommonPorts)
		allResults = append(allResults, results...)
	}

	return allResults
}
