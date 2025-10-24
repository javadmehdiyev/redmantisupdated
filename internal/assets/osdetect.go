package assets

import (
	"strings"
)

// DetectOS performs intelligent OS detection using multiple data sources
// Optimized for best accuracy with proper fallback chain
func DetectOS(ports []PortScanResult, netbiosOS, hostname, macVendor string) string {
	// Priority 1: NetBIOS info (most reliable for Windows)
	if netbiosOS != "" && netbiosOS != "unknown" {
		return netbiosOS
	}

	// Priority 2: Hostname analysis (can be very reliable)
	if osFromHostname := detectOSFromHostname(hostname); osFromHostname != "" {
		return osFromHostname
	}

	// Priority 3: Service banner analysis (high confidence)
	if osFromBanner := detectOSFromBanners(ports); osFromBanner != "" {
		return osFromBanner
	}

	// Priority 4: Port pattern analysis (moderate confidence)
	if osFromPorts := detectOSFromPorts(ports); osFromPorts != "" {
		return osFromPorts
	}

	// Priority 5: MAC vendor-based detection (with device context)
	if osFromVendor := detectOSFromMACVendor(macVendor, len(ports)); osFromVendor != "" {
		return osFromVendor
	}

	// Priority 6: Network device detection (when no ports detected)
	if len(ports) == 0 {
		if osFromInfrastructure := detectOSFromInfrastructure(macVendor); osFromInfrastructure != "" {
			return osFromInfrastructure
		}
	}

	return "Unknown"
}

func detectOSFromBanners(ports []PortScanResult) string {
	if len(ports) == 0 {
		return ""
	}

	var combinedText strings.Builder

	// Build combined text efficiently
	for _, port := range ports {
		if port.Banner != "" {
			combinedText.WriteString(strings.ToLower(port.Banner))
			combinedText.WriteString(" ")
		}
		if port.Service != "" {
			combinedText.WriteString(strings.ToLower(port.Service))
			combinedText.WriteString(" ")
		}
	}

	text := combinedText.String()

	// 1. MOST SPECIFIC SIGNATURES FIRST

	// macOS - very specific indicators
	if strings.Contains(text, "heimdal") {
		return "macOS"
	}
	if strings.Contains(text, "darwin") {
		return "macOS"
	}

	// Windows - check versions first (most specific)
	if strings.Contains(text, "windows server 2022") {
		return "Windows Server 2022"
	}
	if strings.Contains(text, "windows server 2019") {
		return "Windows Server 2019"
	}
	if strings.Contains(text, "windows server 2016") {
		return "Windows Server 2016"
	}
	if strings.Contains(text, "windows server") {
		return "Windows Server"
	}
	if strings.Contains(text, "windows 11") || strings.Contains(text, "win11") {
		return "Windows 11"
	}
	if strings.Contains(text, "windows 10") || strings.Contains(text, "win10") {
		return "Windows 10"
	}

	// Windows - generic indicators
	if strings.Contains(text, "microsoft-ds") ||
		strings.Contains(text, "microsoft windows rpc") ||
		strings.Contains(text, "microsoft-httpapi") {
		return "Windows"
	}
	if strings.Contains(text, "iis") || strings.Contains(text, "exchange") {
		return "Windows Server"
	}
	if strings.Contains(text, "windows") ||
		strings.Contains(text, "win32") ||
		strings.Contains(text, "win64") {
		return "Windows"
	}

	// Linux - distributions (specific to generic)
	if strings.Contains(text, "ubuntu") {
		return "Linux (Ubuntu)"
	}
	if strings.Contains(text, "debian") {
		return "Linux (Debian)"
	}
	if strings.Contains(text, "centos") {
		return "Linux (CentOS)"
	}
	if strings.Contains(text, "red hat") || strings.Contains(text, "rhel") {
		return "Linux (Red Hat)"
	}
	if strings.Contains(text, "fedora") {
		return "Linux (Fedora)"
	}
	if strings.Contains(text, "alpine") {
		return "Linux (Alpine)"
	}
	if strings.Contains(text, "arch linux") {
		return "Linux (Arch)"
	}
	if strings.Contains(text, "linux") {
		return "Linux"
	}

	// BSD variants
	if strings.Contains(text, "freebsd") {
		return "FreeBSD"
	}
	if strings.Contains(text, "openbsd") {
		return "OpenBSD"
	}
	if strings.Contains(text, "netbsd") {
		return "NetBSD"
	}

	// Other Unix-like
	if strings.Contains(text, "solaris") || strings.Contains(text, "sunos") {
		return "Solaris"
	}
	if strings.Contains(text, "unix") {
		return "Unix"
	}

	// Network OS
	if strings.Contains(text, "cisco") {
		return "IOS"
	}
	if strings.Contains(text, "fortinet") || strings.Contains(text, "fortios") {
		return "FortiOS"
	}

	return ""
}

func detectOSFromPorts(ports []PortScanResult) string {
	if len(ports) == 0 {
		return ""
	}

	portMap := make(map[int]bool)
	serviceMap := make(map[string]bool)

	for _, port := range ports {
		portMap[port.Number] = true
		if port.Service != "" {
			serviceMap[strings.ToLower(port.Service)] = true
		}
	}

	// 1. STRONGEST INDICATORS FIRST (single port can determine OS)

	// RPC endpoint mapper = definitely Windows
	if portMap[135] {
		return "Windows"
	}

	// SMB (while Samba exists, port 445 alone is strong Windows indicator)
	if portMap[445] {
		// Check if it's actually Windows SMB vs Samba
		for svc := range serviceMap {
			if strings.Contains(svc, "microsoft") || strings.Contains(svc, "windows") {
				return "Windows"
			}
			if strings.Contains(svc, "samba") {
				return "Linux"
			}
		}
		// Default to Windows if service unclear
		return "Windows"
	}

	// RDP = Windows Desktop/Server
	if portMap[3389] {
		return "Windows"
	}

	// AFP = macOS
	if portMap[548] {
		return "macOS"
	}

	// 2. PORT COMBINATIONS (moderate confidence)

	// Count Windows-specific ports
	windowsPortCount := 0
	if portMap[135] {
		windowsPortCount++
	} // Already returned above, but for scoring
	if portMap[139] {
		windowsPortCount++
	} // NetBIOS
	if portMap[445] {
		windowsPortCount++
	} // SMB
	if portMap[3389] {
		windowsPortCount++
	} // RDP
	if portMap[5985] {
		windowsPortCount++
	} // WinRM
	if portMap[5986] {
		windowsPortCount++
	} // WinRM HTTPS

	// Multiple Windows ports = Windows
	if windowsPortCount >= 2 {
		if portMap[5985] || portMap[5986] {
			return "Windows Server"
		}
		return "Windows"
	}

	// 3. LINUX INDICATORS

	hasSSH := portMap[22]
	hasNoWindowsPorts := windowsPortCount == 0

	if hasSSH && hasNoWindowsPorts {
		// SSH + web server = likely Linux
		if portMap[80] || portMap[443] || portMap[8080] {
			return "Linux"
		}
		// SSH + database = likely Linux
		if portMap[3306] || portMap[5432] || portMap[27017] ||
			portMap[6379] || portMap[9042] || portMap[9200] {
			return "Linux"
		}
		// SSH + NFS = Linux
		if portMap[2049] {
			return "Linux"
		}
		// Just SSH without Windows = likely Linux/Unix
		return "Linux/Unix"
	}

	// 4. OTHER INDICATORS

	// Kerberos (port 88) without Windows ports = macOS
	if portMap[88] && hasNoWindowsPorts {
		return "macOS"
	}

	return ""
}

func detectOSFromHostname(hostname string) string {
	if hostname == "" || hostname == "unknown" {
		return ""
	}

	h := strings.ToLower(hostname)

	// 1. MOST SPECIFIC PATTERNS FIRST

	// Mac-specific naming
	if strings.Contains(h, "macbook") || strings.Contains(h, "imac") ||
		strings.Contains(h, "mac mini") || strings.Contains(h, "macpro") {
		return "macOS"
	}

	// Windows-specific naming (VERY common)
	if strings.HasPrefix(h, "desktop-") || strings.HasPrefix(h, "laptop-") ||
		strings.HasPrefix(h, "win-") || strings.HasPrefix(h, "pc-") {
		return "Windows"
	}
	if strings.Contains(h, "-desktop") || strings.Contains(h, "-pc") ||
		strings.Contains(h, "-win") || strings.Contains(h, "windows") {
		return "Windows"
	}

	// Server patterns
	if strings.Contains(h, "srv") || strings.Contains(h, "server") {
		return "Windows Server"
	}

	// .local domain analysis
	if strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".local.") {
		// If no Windows indicators, likely macOS
		if !strings.Contains(h, "desktop") && !strings.Contains(h, "laptop") &&
			!strings.Contains(h, "pc") && !strings.Contains(h, "win") {
			return "macOS"
		}
	}

	// Linux distributions
	if strings.Contains(h, "ubuntu") {
		return "Linux (Ubuntu)"
	}
	if strings.Contains(h, "debian") {
		return "Linux (Debian)"
	}
	if strings.Contains(h, "centos") {
		return "Linux (CentOS)"
	}
	if strings.Contains(h, "rhel") {
		return "Linux (Red Hat)"
	}
	if strings.Contains(h, "linux") {
		return "Linux"
	}

	return ""
}

func detectOSFromMACVendor(macVendor string, portCount int) string {
	if macVendor == "" || macVendor == "Unknown Vendor" {
		return ""
	}

	v := strings.ToLower(macVendor)

	// 1. APPLE DEVICES (context-aware)
	if strings.Contains(v, "apple") {
		if portCount > 5 {
			return "macOS" // Mac computers typically have many services
		}
		if portCount >= 1 && portCount <= 5 {
			return "iOS/iPadOS" // Mobile devices have few services
		}
		return "macOS/iOS" // Unknown, could be either
	}

	// 2. MICROSOFT DEVICES
	if strings.Contains(v, "microsoft") {
		return "Windows"
	}

	// 3. LINUX/EMBEDDED DEVICES
	if strings.Contains(v, "raspberry") {
		return "Linux (Raspberry Pi OS)"
	}
	if strings.Contains(v, "espressif") {
		return "Embedded Linux/RTOS"
	}

	// 4. COMPUTER MANUFACTURERS (most run Windows)
	if strings.Contains(v, "dell") || strings.Contains(v, "hp") ||
		strings.Contains(v, "lenovo") || strings.Contains(v, "asus") ||
		strings.Contains(v, "acer") || strings.Contains(v, "msi") ||
		strings.Contains(v, "azurewave") || strings.Contains(v, "intel") {
		return "Windows" // Most likely Windows
	}

	return ""
}

// detectOSFromInfrastructure detects OS for network infrastructure devices
func detectOSFromInfrastructure(macVendor string) string {
	if macVendor == "" || macVendor == "Unknown Vendor" {
		return ""
	}

	v := strings.ToLower(macVendor)

	// 1. MAJOR NETWORK VENDORS
	if strings.Contains(v, "cisco") {
		return "IOS/IOS-XE"
	}
	if strings.Contains(v, "fortinet") {
		return "FortiOS"
	}
	if strings.Contains(v, "palo alto") {
		return "PAN-OS"
	}
	if strings.Contains(v, "juniper") {
		return "Junos"
	}
	if strings.Contains(v, "mikrotik") {
		return "RouterOS"
	}
	if strings.Contains(v, "ubiquiti") {
		return "UniFi OS/EdgeOS"
	}
	if strings.Contains(v, "aruba") {
		return "ArubaOS"
	}

	// 2. CONSUMER NETWORK DEVICES (Embedded Linux)
	if strings.Contains(v, "netgear") || strings.Contains(v, "tp-link") ||
		strings.Contains(v, "d-link") || strings.Contains(v, "linksys") ||
		strings.Contains(v, "asus") && strings.Contains(v, "router") {
		return "Embedded Linux"
	}

	// 3. VIRTUALIZATION
	if strings.Contains(v, "vmware") {
		return "Guest OS"
	}

	// 4. PRINTERS (many have embedded OS)
	if strings.Contains(v, "hewlett-packard") || strings.Contains(v, "canon") ||
		strings.Contains(v, "epson") || strings.Contains(v, "brother") {
		return "Embedded OS"
	}

	return ""
}
