package scanning

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"redmantis/internal/assets"
)

// PortScanner represents a fast, native Go port scanner
type PortScanner struct {
	timeout        time.Duration
	maxWorkers     int
	bannerTimeout  time.Duration
	connectTimeout time.Duration
}

// NewPortScanner creates a new port scanner with default settings
func NewPortScanner(timeout time.Duration, workers int) *PortScanner {
	return &PortScanner{
		timeout:        timeout,
		maxWorkers:     workers,
		bannerTimeout:  3 * time.Second,
		connectTimeout: 2 * time.Second,
	}
}

// ScanHost scans a single host for open ports
func (ps *PortScanner) ScanHost(ip string, ports []int) []assets.PortResult {
	var results []assets.PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create worker pool
	semaphore := make(chan struct{}, ps.maxWorkers)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Scan port
			if isOpen, service, banner := ps.scanPort(ip, p); isOpen {
				mu.Lock()
				results = append(results, assets.PortResult{
					Port:      p,
					State:     true,
					Service:   service,
					Banner:    banner,
					Protocol:  "tcp",
					IPAddress: ip,
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// scanPort scans a single port and returns status, service, and banner
func (ps *PortScanner) scanPort(ip string, port int) (bool, string, string) {
	// Handle IPv6 addresses properly
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// Try to connect
	conn, err := net.DialTimeout("tcp", address, ps.connectTimeout)
	if err != nil {
		return false, "", ""
	}
	defer conn.Close()

	// Port is open, now grab banner
	service, banner := ps.grabBanner(conn, port)

	return true, service, banner
}

// grabBanner attempts to grab service banner and identify the service
func (ps *PortScanner) grabBanner(conn net.Conn, port int) (string, string) {
	conn.SetReadDeadline(time.Now().Add(ps.bannerTimeout))

	var banner string
	var service string

	// Try different banner grabbing strategies based on port
	switch port {
	case 21: // FTP
		banner = ps.readBanner(conn, 1024)
		service = ps.identifyFTP(banner)

	case 22: // SSH
		banner = ps.readBanner(conn, 1024)
		service = ps.identifySSH(banner)

	case 23: // Telnet
		banner = ps.readBanner(conn, 1024)
		service = "Telnet"

	case 25, 110, 143, 587, 993, 995: // Mail services
		banner = ps.readBanner(conn, 1024)
		service = ps.identifyMailService(port, banner)

	case 80, 8080, 8000, 8888, 9000: // HTTP
		banner = ps.grabHTTPBanner(conn)
		service = ps.identifyHTTP(banner)

	case 443, 8443: // HTTPS
		service = "HTTPS"
		banner = "SSL/TLS"

	case 3306: // MySQL
		banner = ps.readBanner(conn, 512)
		service = ps.identifyMySQL(banner)

	case 5432: // PostgreSQL
		banner = ps.readBanner(conn, 512)
		service = "PostgreSQL"

	case 6379: // Redis
		conn.Write([]byte("PING\r\n"))
		banner = ps.readBanner(conn, 512)
		service = "Redis"

	case 27017: // MongoDB
		service = "MongoDB"
		banner = "MongoDB Server"

	case 135, 139, 445: // Windows services
		service = ps.identifyWindowsService(port)
		banner = service

	case 3389: // RDP
		service = "Microsoft RDP"
		banner = "Remote Desktop Protocol"

	case 5900, 5901: // VNC
		banner = ps.readBanner(conn, 512)
		service = "VNC"

	case 1433: // MSSQL
		service = "Microsoft SQL Server"
		banner = "MSSQL"

	case 161: // SNMP
		service = "SNMP"
		banner = "Simple Network Management Protocol"

	default:
		// Generic banner grab
		banner = ps.readBanner(conn, 1024)
		service = ps.identifyGenericService(port, banner)
	}

	// If no service identified, use port-based default
	if service == "" {
		service = ps.getDefaultServiceName(port)
	}

	return service, banner
}

// readBanner reads data from connection
func (ps *PortScanner) readBanner(conn net.Conn, maxBytes int) string {
	buffer := make([]byte, maxBytes)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
}

// grabHTTPBanner sends HTTP request and reads response
func (ps *PortScanner) grabHTTPBanner(conn net.Conn) string {
	request := "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(request))

	scanner := bufio.NewScanner(conn)
	var headers []string
	for scanner.Scan() && len(headers) < 10 {
		line := scanner.Text()
		if line == "" {
			break
		}
		headers = append(headers, line)
	}

	return strings.Join(headers, " ")
}

// Service identification methods

func (ps *PortScanner) identifySSH(banner string) string {
	if banner == "" {
		return "SSH"
	}

	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "openssh") {
		// Extract version
		if strings.Contains(banner, "OpenSSH") {
			return extractVersion(banner, "OpenSSH")
		}
		return "OpenSSH"
	}
	if strings.Contains(bannerLower, "dropbear") {
		return "Dropbear SSH"
	}
	if strings.Contains(bannerLower, "ssh") {
		return "SSH Server"
	}

	return "SSH"
}

func (ps *PortScanner) identifyFTP(banner string) string {
	if banner == "" {
		return "FTP"
	}

	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "vsftpd") {
		return extractVersion(banner, "vsftpd")
	}
	if strings.Contains(bannerLower, "proftpd") {
		return extractVersion(banner, "ProFTPD")
	}
	if strings.Contains(bannerLower, "filezilla") {
		return "FileZilla FTP"
	}
	if strings.Contains(bannerLower, "microsoft ftp") {
		return "Microsoft FTP"
	}

	return "FTP Server"
}

func (ps *PortScanner) identifyHTTP(banner string) string {
	if banner == "" {
		return "HTTP"
	}

	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "apache") {
		return extractVersion(banner, "Apache")
	}
	if strings.Contains(bannerLower, "nginx") {
		return extractVersion(banner, "nginx")
	}
	if strings.Contains(bannerLower, "microsoft-iis") || strings.Contains(bannerLower, "iis") {
		return extractVersion(banner, "IIS")
	}
	if strings.Contains(bannerLower, "lighttpd") {
		return "Lighttpd"
	}

	return "HTTP Server"
}

func (ps *PortScanner) identifyMySQL(banner string) string {
	if banner == "" {
		return "MySQL"
	}

	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "mariadb") {
		return "MariaDB"
	}
	if strings.Contains(bannerLower, "mysql") {
		return extractVersion(banner, "MySQL")
	}

	return "MySQL Server"
}

func (ps *PortScanner) identifyMailService(port int, banner string) string {
	bannerLower := strings.ToLower(banner)

	switch port {
	case 25, 587:
		if strings.Contains(bannerLower, "postfix") {
			return "Postfix SMTP"
		}
		if strings.Contains(bannerLower, "exchange") {
			return "Microsoft Exchange"
		}
		return "SMTP"
	case 110, 995:
		return "POP3"
	case 143, 993:
		if strings.Contains(bannerLower, "dovecot") {
			return "Dovecot IMAP"
		}
		return "IMAP"
	}

	return "Mail Service"
}

func (ps *PortScanner) identifyWindowsService(port int) string {
	switch port {
	case 135:
		return "Microsoft Windows RPC"
	case 139:
		return "NetBIOS Session Service"
	case 445:
		return "Microsoft DS (SMB)"
	}
	return "Windows Service"
}

func (ps *PortScanner) identifyGenericService(port int, banner string) string {
	if banner == "" {
		return ""
	}

	bannerLower := strings.ToLower(banner)

	// Check for common keywords
	if strings.Contains(bannerLower, "http") {
		return "HTTP"
	}
	if strings.Contains(bannerLower, "ssh") {
		return "SSH"
	}
	if strings.Contains(bannerLower, "ftp") {
		return "FTP"
	}
	if strings.Contains(bannerLower, "smtp") {
		return "SMTP"
	}
	if strings.Contains(bannerLower, "mysql") {
		return "MySQL"
	}
	if strings.Contains(bannerLower, "postgres") {
		return "PostgreSQL"
	}
	if strings.Contains(bannerLower, "redis") {
		return "Redis"
	}
	if strings.Contains(bannerLower, "mongo") {
		return "MongoDB"
	}

	return ""
}

func (ps *PortScanner) getDefaultServiceName(port int) string {
	serviceMap := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		88:    "Kerberos",
		110:   "POP3",
		135:   "MSRPC",
		139:   "NetBIOS",
		143:   "IMAP",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		2049:  "NFS",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-alt",
		8443:  "HTTPS-alt",
		9042:  "Cassandra",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}

	if service, found := serviceMap[port]; found {
		return service
	}

	return fmt.Sprintf("Port %d", port)
}

// extractVersion attempts to extract version from banner
func extractVersion(banner, productName string) string {
	// Find product name in banner (case insensitive)
	idx := strings.Index(strings.ToLower(banner), strings.ToLower(productName))
	if idx == -1 {
		return productName
	}

	// Extract the portion after product name
	rest := banner[idx+len(productName):]

	// Look for version pattern (e.g., "2.4.41", "1.18.0")
	parts := strings.Fields(rest)
	for _, part := range parts {
		// Remove common separators
		part = strings.Trim(part, "/()-")

		// Check if it looks like a version number
		if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
			return productName + " " + part
		}
	}

	return productName
}
