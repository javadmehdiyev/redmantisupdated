package assets

import (
	"strings"
)

// DetectHardware infers hardware type from MAC vendor, device type, OS, and service patterns
func DetectHardware(macVendor, deviceType, os string, ports []PortScanResult) string {
	// Priority 1: Check specific service patterns (highest confidence)
	if hwFromServices := detectHardwareFromServices(ports, os); hwFromServices != "" {
		return hwFromServices
	}

	// Priority 2: Check MAC vendor for specific hardware hints
	if hwFromVendor := detectHardwareFromVendor(macVendor, deviceType, os); hwFromVendor != "" {
		return hwFromVendor
	}

	// Priority 3: Check device type and OS combination
	if hwFromDeviceType := detectHardwareFromDeviceType(deviceType, os); hwFromDeviceType != "" {
		return hwFromDeviceType
	}

	// Default fallback
	return "Unknown"
}

func detectHardwareFromVendor(macVendor, deviceType, os string) string {
	if macVendor == "" || macVendor == "Unknown Vendor" {
		return ""
	}

	vendorLower := strings.ToLower(macVendor)
	osLower := strings.ToLower(os)
	deviceTypeLower := strings.ToLower(deviceType)

	// Apple hardware detection
	if strings.Contains(vendorLower, "apple") {
		// Determine if it's a Mac, iPhone, iPad based on OS and device type
		if strings.Contains(osLower, "macos") || strings.Contains(deviceType, "Workstation") {
			return "Mac (Desktop/Laptop)"
		}
		if strings.Contains(osLower, "ios") || strings.Contains(deviceType, "Mobile") {
			return "iPhone/iPad"
		}
		// Default Apple device
		return "Apple Device"
	}

	// Mobile phone vendors (Expanded)
	mobileVendors := map[string]string{
		"samsung":        "Samsung Mobile Device",
		"huawei":         "Huawei Mobile Device",
		"xiaomi":         "Xiaomi Mobile Device",
		"oneplus":        "OnePlus Device",
		"google":         "Google Pixel Device",
		"lg electronics": "LG Mobile Device",
		"motorola":       "Motorola Device",
		"nokia":          "Nokia Device",
		"sony mobile":    "Sony Xperia",
		"htc":            "HTC Device",
		"oppo":           "OPPO Device",
		"vivo":           "Vivo Device",
		"realme":         "Realme Device",
		"honor":          "Honor Device",
		"zte":            "ZTE Device",
		"tcl":            "TCL Device",
	}

	for vendor, hardware := range mobileVendors {
		if strings.Contains(vendorLower, vendor) {
			return hardware
		}
	}

	// Computer/Server manufacturers
	computerVendors := map[string]string{
		"dell":       "Dell Computer/Server",
		"hp":         "HP Computer/Server",
		"lenovo":     "Lenovo Computer",
		"asus":       "ASUS Computer",
		"acer":       "Acer Computer",
		"msi":        "MSI Computer",
		"intel":      "Intel-based Device",
		"gigabyte":   "Gigabyte Computer",
		"supermicro": "Supermicro Server",
	}

	for vendor, hardware := range computerVendors {
		if strings.Contains(vendorLower, vendor) {
			// Distinguish between server and desktop based on device type
			if strings.Contains(deviceType, "Server") {
				return strings.Replace(hardware, "Computer", "Server", 1)
			}
			return hardware
		}
	}

	// Network equipment vendors
	networkVendors := map[string]string{
		"cisco":     "Cisco Network Device",
		"fortinet":  "Fortinet Firewall",
		"palo alto": "Palo Alto Firewall",
		"juniper":   "Juniper Network Device",
		"aruba":     "Aruba Network Device",
		"ubiquiti":  "Ubiquiti Network Device",
		"mikrotik":  "MikroTik Router",
		"netgear":   "Netgear Network Device",
		"tp-link":   "TP-Link Network Device",
		"d-link":    "D-Link Network Device",
	}

	for vendor, hardware := range networkVendors {
		if strings.Contains(vendorLower, vendor) {
			return hardware
		}
	}

	// AzureWave Technology (common in laptops/desktops)
	if strings.Contains(vendorLower, "azurewave") {
		if strings.Contains(osLower, "windows") {
			return "Windows PC"
		}
		return "Computer/Laptop"
	}

	// Printer manufacturers
	printerVendors := map[string]string{
		"hewlett-packard": "HP Printer",
		"canon":           "Canon Printer",
		"epson":           "Epson Printer",
		"brother":         "Brother Printer",
		"lexmark":         "Lexmark Printer",
		"xerox":           "Xerox Printer",
	}

	for vendor, hardware := range printerVendors {
		if strings.Contains(vendorLower, vendor) {
			return hardware
		}
	}

	// IoT/Embedded devices
	iotVendors := map[string]string{
		"raspberry":         "Raspberry Pi",
		"espressif":         "ESP-based IoT Device",
		"arduino":           "Arduino Device",
		"texas instruments": "TI Embedded Device",
	}

	for vendor, hardware := range iotVendors {
		if strings.Contains(vendorLower, vendor) {
			return hardware
		}
	}

	// VMware virtual machines
	if strings.Contains(vendorLower, "vmware") {
		if strings.Contains(osLower, "windows") {
			return "VMware Virtual Machine (Windows)"
		} else if strings.Contains(osLower, "linux") {
			return "VMware Virtual Machine (Linux)"
		}
		return "VMware Virtual Machine"
	}

	// VirtualBox VMs
	if strings.Contains(vendorLower, "virtualbox") {
		return "VirtualBox Virtual Machine"
	}

	// Microsoft Hyper-V (check Oracle separately for VirtualBox)
	if strings.Contains(vendorLower, "microsoft") {
		if strings.Contains(deviceTypeLower, "server") || strings.Contains(deviceTypeLower, "virtual") {
			return "Hyper-V Virtual Machine"
		}
		return "Microsoft Device"
	}

	return ""
}

func detectHardwareFromDeviceType(deviceType, os string) string {
	if deviceType == "" || deviceType == "Unknown" {
		return ""
	}

	deviceTypeLower := strings.ToLower(deviceType)
	osLower := strings.ToLower(os)

	// Server hardware
	if strings.Contains(deviceTypeLower, "server") {
		if strings.Contains(osLower, "windows") {
			return "Windows Server Hardware"
		}
		if strings.Contains(osLower, "linux") {
			return "Linux Server Hardware"
		}
		return "Server Hardware"
	}

	// Workstation
	if strings.Contains(deviceTypeLower, "workstation") {
		if strings.Contains(osLower, "windows") {
			return "Windows PC"
		}
		if strings.Contains(osLower, "linux") {
			return "Linux Workstation"
		}
		if strings.Contains(osLower, "macos") {
			return "Mac Computer"
		}
		return "Desktop Computer"
	}

	// Mobile device
	if strings.Contains(deviceTypeLower, "mobile") {
		return "Mobile Phone/Tablet"
	}

	// Printer
	if strings.Contains(deviceTypeLower, "printer") {
		return "Network Printer"
	}

	// Router
	if strings.Contains(deviceTypeLower, "router") {
		return "Router/Gateway"
	}

	// Network infrastructure
	if strings.Contains(deviceTypeLower, "network infrastructure") {
		return "Network Switch/Appliance"
	}

	// IoT
	if strings.Contains(deviceTypeLower, "iot") {
		return "IoT Device"
	}

	return ""
}

func detectHardwareFromServices(ports []PortScanResult, os string) string {
	// Check for Kerberos + macOS = likely Mac computer
	for _, port := range ports {
		serviceLower := strings.ToLower(port.Service)
		bannerLower := strings.ToLower(port.Banner)

		// Heimdal Kerberos indicates macOS
		if (strings.Contains(serviceLower, "kerberos") || strings.Contains(bannerLower, "kerberos")) &&
			strings.Contains(bannerLower, "heimdal") {
			return "Mac Computer"
		}

		// ESXi indicates VMware server
		if strings.Contains(serviceLower, "esxi") || strings.Contains(bannerLower, "esxi") {
			return "VMware ESXi Server"
		}

		// iLO/iDRAC indicates server management
		if strings.Contains(serviceLower, "ilo") || strings.Contains(bannerLower, "ilo") {
			return "HP Server (iLO)"
		}
		if strings.Contains(serviceLower, "idrac") || strings.Contains(bannerLower, "idrac") {
			return "Dell Server (iDRAC)"
		}

		// IPMI indicates server with BMC
		if strings.Contains(serviceLower, "ipmi") || port.Number == 623 {
			return "Server with IPMI/BMC"
		}
	}

	// Check for container/virtualization platforms
	for _, port := range ports {
		serviceLower := strings.ToLower(port.Service)
		bannerLower := strings.ToLower(port.Banner)

		if strings.Contains(serviceLower, "docker") || strings.Contains(bannerLower, "docker") {
			return "Docker Host"
		}
		if strings.Contains(serviceLower, "kubernetes") || strings.Contains(bannerLower, "kubernetes") {
			return "Kubernetes Node"
		}
	}

	return ""
}
