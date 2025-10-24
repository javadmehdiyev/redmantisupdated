package assets

import (
	"strings"
)

// ClassifyDeviceType infers device type based on open ports, services, and MAC vendor
func ClassifyDeviceType(ports []PortScanResult, macVendor string) string {
	if len(ports) == 0 {
		return classifyByMACVendor(macVendor)
	}

	// Build port and service maps for easy lookup
	portMap := make(map[int]bool)
	serviceMap := make(map[string]bool)
	var allServices []string

	for _, port := range ports {
		portMap[port.Number] = true
		serviceLower := strings.ToLower(port.Service)
		allServices = append(allServices, serviceLower)
		if serviceLower != "" {
			serviceMap[serviceLower] = true
		}
		// Also check banner
		bannerLower := strings.ToLower(port.Banner)
		if bannerLower != "" {
			serviceMap[bannerLower] = true
		}
	}

	var types []string

	// Check for printer
	if isPrinter(portMap, serviceMap) {
		types = append(types, "Printer")
	}

	// Check for router/network infrastructure
	if isRouter(portMap, serviceMap, len(ports)) {
		types = append(types, "Router")
	}

	// Check for web server
	if isWebServer(portMap, serviceMap) {
		types = append(types, "Web Server")
	}

	// Check for database server
	if dbType := getDatabaseType(portMap, serviceMap); dbType != "" {
		types = append(types, dbType)
	}

	// Check for mail server
	if isMailServer(portMap, serviceMap) {
		types = append(types, "Mail Server")
	}

	// Check for file server
	if isFileServer(portMap, serviceMap) {
		types = append(types, "File Server")
	}

	// Check for DNS server
	if portMap[53] {
		types = append(types, "DNS Server")
	}

	// Check for workstation/desktop
	if isWorkstation(portMap, serviceMap) {
		types = append(types, "Workstation")
	}

	// Check for IoT device
	if isIoTDevice(portMap, serviceMap, macVendor, len(ports)) {
		types = append(types, "IoT Device")
	}

	// Check for mobile device
	if isMobileDevice(macVendor, len(ports)) {
		types = append(types, "Mobile Device")
	}

	// Check for network infrastructure
	if isNetworkInfrastructure(portMap, serviceMap, len(ports)) && !contains(types, "Router") {
		types = append(types, "Network Infrastructure")
	}

	// If no specific type identified, try MAC vendor classification
	if len(types) == 0 {
		return classifyByMACVendor(macVendor)
	}

	return strings.Join(types, ", ")
}

func isPrinter(portMap map[int]bool, serviceMap map[string]bool) bool {
	printerPorts := []int{515, 631, 9100}
	for _, port := range printerPorts {
		if portMap[port] {
			return true
		}
	}

	printerServices := []string{"printer", "ipp", "lpd", "jetdirect"}
	for _, svc := range printerServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return false
}

func isRouter(portMap map[int]bool, serviceMap map[string]bool, portCount int) bool {
	// Routers typically have web interface, SSH, and SNMP
	hasWebInterface := portMap[80] || portMap[443] || portMap[8080]
	hasSSH := portMap[22]
	hasSNMP := portMap[161]
	hasTelnet := portMap[23]

	// Router characteristic: management ports but not typical server services
	hasNoServerServices := !portMap[3306] && !portMap[5432] && !portMap[27017] && !portMap[1433]

	return (hasWebInterface && (hasSSH || hasTelnet) && hasSNMP && hasNoServerServices) ||
		(hasWebInterface && hasSNMP && portCount <= 10)
}

func isWebServer(portMap map[int]bool, serviceMap map[string]bool) bool {
	webPorts := []int{80, 443, 8080, 8443, 8000, 8888}
	for _, port := range webPorts {
		if portMap[port] {
			return true
		}
	}

	webServices := []string{"http", "https", "apache", "nginx", "iis", "lighttpd", "caddy"}
	for _, svc := range webServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return false
}

func getDatabaseType(portMap map[int]bool, serviceMap map[string]bool) string {
	// Check service names first for more accurate detection
	dbServices := map[string]string{
		"mysql":         "MySQL Server",
		"postgresql":    "PostgreSQL Server",
		"postgres":      "PostgreSQL Server",
		"mongodb":       "MongoDB Server",
		"redis":         "Redis Server",
		"mssql":         "MSSQL Server",
		"sql server":    "MSSQL Server",
		"couchdb":       "CouchDB Server",
		"cassandra":     "Cassandra Server",
		"elasticsearch": "Elasticsearch Server",
	}

	for svc, dbType := range dbServices {
		if containsService(serviceMap, svc) {
			return dbType
		}
	}

	// Then check port numbers (less reliable)
	databases := map[int]string{
		3306:  "MySQL Server",
		5432:  "PostgreSQL Server",
		27017: "MongoDB Server",
		6379:  "Redis Server",
		1433:  "MSSQL Server",
		5984:  "CouchDB Server",
		9042:  "Cassandra Server",
		9200:  "Elasticsearch Server",
	}

	for port, dbType := range databases {
		if portMap[port] {
			return dbType
		}
	}

	return ""
}

func isMailServer(portMap map[int]bool, serviceMap map[string]bool) bool {
	mailPorts := []int{25, 110, 143, 465, 587, 993, 995}
	count := 0
	for _, port := range mailPorts {
		if portMap[port] {
			count++
		}
	}

	if count >= 2 {
		return true
	}

	mailServices := []string{"smtp", "pop3", "imap", "postfix", "sendmail", "exchange"}
	for _, svc := range mailServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return false
}

func isFileServer(portMap map[int]bool, serviceMap map[string]bool) bool {
	// SMB/CIFS
	if portMap[445] || portMap[139] {
		return true
	}

	// NFS
	if portMap[2049] {
		return true
	}

	// FTP with data port
	if portMap[21] && portMap[20] {
		return true
	}

	fileServices := []string{"smb", "cifs", "samba", "nfs", "ftp", "sftp", "microsoft-ds", "netbios"}
	for _, svc := range fileServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return false
}

func isWorkstation(portMap map[int]bool, serviceMap map[string]bool) bool {
	// RDP
	if portMap[3389] {
		return true
	}

	// VNC
	if portMap[5900] || portMap[5901] {
		return true
	}

	workstationServices := []string{"rdp", "vnc", "remote desktop"}
	for _, svc := range workstationServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return false
}

func isIoTDevice(portMap map[int]bool, serviceMap map[string]bool, macVendor string, portCount int) bool {
	// IoT devices typically have limited open ports
	if portCount > 10 {
		return false
	}

	iotPorts := []int{1883, 8883, 5683, 5684} // MQTT, CoAP
	for _, port := range iotPorts {
		if portMap[port] {
			return true
		}
	}

	iotServices := []string{"mqtt", "coap", "iot", "sensor"}
	for _, svc := range iotServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	// Check MAC vendor for common IoT manufacturers
	iotVendors := []string{"Espressif", "Raspberry", "Arduino", "ESP", "IoT"}
	vendorLower := strings.ToLower(macVendor)
	for _, vendor := range iotVendors {
		if strings.Contains(vendorLower, strings.ToLower(vendor)) {
			return true
		}
	}

	return false
}

func isMobileDevice(macVendor string, portCount int) bool {
	// Mobile devices typically have very few open ports
	if portCount > 5 {
		return false
	}

	mobileVendors := []string{"Apple", "Samsung", "Huawei", "Xiaomi", "OnePlus", "Google", "LG Electronics"}
	vendorLower := strings.ToLower(macVendor)
	for _, vendor := range mobileVendors {
		if strings.Contains(vendorLower, strings.ToLower(vendor)) && portCount <= 3 {
			return true
		}
	}

	return false
}

func isNetworkInfrastructure(portMap map[int]bool, serviceMap map[string]bool, portCount int) bool {
	// Network infrastructure: primarily SNMP, SSH, Telnet
	hasManagementOnly := (portMap[161] || portMap[22] || portMap[23]) && portCount <= 5

	infraServices := []string{"snmp", "network", "switch", "infrastructure"}
	for _, svc := range infraServices {
		if containsService(serviceMap, svc) {
			return true
		}
	}

	return hasManagementOnly
}

func classifyByMACVendor(macVendor string) string {
	if macVendor == "" || macVendor == "Unknown Vendor" {
		return "Unknown"
	}

	vendorLower := strings.ToLower(macVendor)

	// Network equipment (FIRST - highest priority for infrastructure devices)
	networkVendors := map[string]string{
		"cisco":     "Router/Firewall",
		"fortinet":  "Firewall",
		"palo alto": "Firewall",
		"juniper":   "Router",
		"aruba":     "Network Infrastructure",
		"ubiquiti":  "Network Infrastructure",
		"mikrotik":  "Router",
		"netgear":   "Network Infrastructure",
		"tp-link":   "Network Infrastructure",
		"d-link":    "Network Infrastructure",
	}

	for vendor, deviceType := range networkVendors {
		if strings.Contains(vendorLower, vendor) {
			return deviceType
		}
	}

	// Virtual machines
	if strings.Contains(vendorLower, "vmware") {
		return "Virtual Machine"
	}

	// Mobile devices
	mobileVendors := map[string]string{
		"apple":   "Mobile Device",
		"samsung": "Mobile Device",
		"huawei":  "Mobile Device",
		"xiaomi":  "Mobile Device",
		"oneplus": "Mobile Device",
		"google":  "Mobile Device",
	}

	for vendor, deviceType := range mobileVendors {
		if strings.Contains(vendorLower, vendor) {
			return deviceType
		}
	}

	// Printers
	printerVendors := []string{"hp", "hewlett-packard", "canon", "epson", "brother", "lexmark", "xerox"}
	for _, vendor := range printerVendors {
		if strings.Contains(vendorLower, vendor) {
			return "Printer"
		}
	}

	// IoT
	iotVendors := []string{"espressif", "raspberry", "arduino", "iot"}
	for _, vendor := range iotVendors {
		if strings.Contains(vendorLower, vendor) {
			return "IoT Device"
		}
	}

	// Computer manufacturers
	computerVendors := []string{"dell", "lenovo", "asus", "acer", "msi", "intel", "amd", "azurewave"}
	for _, vendor := range computerVendors {
		if strings.Contains(vendorLower, vendor) {
			return "Workstation"
		}
	}

	return "Unknown"
}

func containsService(serviceMap map[string]bool, search string) bool {
	for service := range serviceMap {
		if strings.Contains(service, search) {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
