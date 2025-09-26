# RedMantis v2 - Network Discovery & Asset Management

RedMantis v2 is a comprehensive network discovery and asset management tool that combines multiple scanning techniques to provide complete visibility into your network infrastructure. It features both a powerful CLI scanner and a REST API for programmatic access to discovered assets.

## 🚀 Features

### Core Network Discovery
- **ARP Scanning**: Discovers active hosts and their MAC addresses
- **Passive Discovery**: Monitors network traffic without generating packets
- **mDNS Discovery**: Finds services and devices using multicast DNS
- **ICMP & TCP Scanning**: Comprehensive host discovery and port scanning
- **Advanced Port Scanning**: Detailed service detection with banner grabbing

### Asset Management
- **Complete Asset Inventory**: IP addresses, hostnames, MAC addresses, OS detection
- **Service Discovery**: Open ports, running services, and service banners
- **Credential Testing**: Automated testing of default credentials across services
- **Hardware Detection**: MAC vendor identification and hardware fingerprinting

### API & Integration
- **REST API**: Full programmatic access to discovered assets
- **Swagger Documentation**: Interactive API documentation
- **JSON Export**: Structured data export for integration with other tools
- **Pagination Support**: Efficient handling of large asset inventories

## 📁 Project Structure

```
redmantisv2/
├── main.go                                    # Main CLI application entry point
├── api/                                       # REST API server
│   ├── main.go                               # API server implementation
│   ├── docs/                                 # Swagger documentation
│   │   ├── docs.go
│   │   ├── swagger.json
│   │   └── swagger.yaml
│   ├── go.mod
│   └── go.sum
├── credtestserver/                           # Credential testing service
│   └── app.py                               # Python Flask server for credential testing
├── advanced_port_scanner.go                  # Advanced port scanning with nmap integration
├── arpEveryHostForGettingTheirMacAddress.go  # ARP scanning for host discovery
├── getAllHostsInTheNetwork.go               # Network range enumeration
├── getNetworkInterfaceAndLocalNetwork.go    # Network interface detection
├── icmpAndTcpScan.go                        # ICMP and TCP scanning
├── mac_lookup.go                            # MAC address vendor lookup
├── mdns.go                                  # mDNS service discovery
├── passiveDiscovery.go                      # Passive network monitoring
├── synScan.go                               # SYN scanning implementation
├── go.mod                                   # Main Go module dependencies
└── go.sum                                   # Go module checksums
```

## 🛠️ Installation

### Prerequisites
- Go 1.25.0 or later
- Python 3.7+ (for credential testing server)
- nmap (for advanced port scanning)
- Root/Administrator privileges (for raw socket operations)

### Main Scanner Installation
```bash
# Clone the repository
git clone <repository-url>
cd redmantisv2

# Install dependencies
go mod tidy

# Build the main scanner
go build -o redmantis main.go
```

### API Server Installation
```bash
# Navigate to API directory
cd api

# Install API dependencies
go mod tidy

# Build the API server
go build -o redmantis-api main.go
```

### Credential Testing Server Installation
```bash
# Navigate to credential testing server
cd credtestserver

# Install Python dependencies
pip install flask paramiko ftplib

# The server is ready to run
python app.py
```

## 🚀 Usage

### CLI Scanner

Run the main network scanner:
```bash
sudo ./redmantis
```

The scanner will:
1. Detect your network interface and local network range
2. Perform ARP scanning to discover active hosts
3. Get MAC addresses and vendor information
4. Perform passive discovery to find additional hosts
5. Run mDNS discovery for service enumeration
6. Execute advanced port scanning on discovered hosts
7. Test default credentials on discovered services
8. Export results to `results.json`

### API Server

Start the REST API server:
```bash
cd api
./redmantis-api
```

The API will be available at `http://localhost:8080`

#### API Endpoints

- **GET /assets** - Get paginated list of all discovered assets
  - Query parameters: `page` (default: 1), `size` (default: 10)
- **GET /assets/{ip}** - Get detailed information about a specific asset by IP
- **GET /swagger/index.html** - Interactive Swagger documentation

#### Example API Usage

```bash
# Get all assets (paginated)
curl "http://localhost:8080/assets?page=1&size=20"

# Get specific asset by IP
curl "http://localhost:8080/assets/192.168.1.100"

# Access Swagger documentation
open http://localhost:8080/swagger/index.html
```

### Credential Testing Server

Start the credential testing service:
```bash
cd credtestserver
python app.py
```

This service provides automated testing of default credentials across various services including:
- SSH
- FTP
- Telnet
- HTTP Basic Auth
- MySQL
- PostgreSQL
- MongoDB
- Redis
- And more...

## 📊 Output Format

### Asset Data Structure

```json
{
  "address": "192.168.1.100",
  "hostname": "device.local",
  "os": "Linux 5.4.0",
  "type": "server",
  "hardware": "x86_64",
  "mac_vendor": "Intel Corporation",
  "mac": "00:11:22:33:44:55",
  "screenshot": "",
  "date": "2025-01-27T10:30:00Z",
  "ports": [
    {
      "number": 22,
      "service": "SSH",
      "banner": "OpenSSH 8.2p1",
      "state": "open",
      "transport": "tcp"
    }
  ],
  "credential_tests": [
    {
      "service": "ssh",
      "username": "admin",
      "password": "admin",
      "success": false
    }
  ]
}
```

## 🔧 Configuration

### Network Interface Selection
The scanner automatically detects your primary network interface. To specify a different interface, modify the network detection logic in `getNetworkInterfaceAndLocalNetwork.go`.

### Scanning Parameters
- **ARP Scan Timeout**: Configurable in `arpEveryHostForGettingTheirMacAddress.go`
- **Port Scan Range**: Modify the port ranges in `advanced_port_scanner.go`
- **Passive Discovery Duration**: Adjustable in `passiveDiscovery.go`
- **mDNS Discovery Timeout**: Configurable in `mdns.go`

### API Configuration
- **Port**: Default 8080, change in `api/main.go`
- **Results File**: Default `../results.json`, modify in `loadAssetsFromJSON()`

## 🛡️ Security Considerations

- **Root Privileges**: Required for raw socket operations and packet capture
- **Network Impact**: The scanner generates network traffic; use responsibly
- **Credential Testing**: Only tests default/weak credentials; ensure proper authorization
- **Passive Mode**: Use passive discovery in sensitive environments to minimize network impact

## 🔍 Scanning Techniques

### Active Discovery
- **ARP Scanning**: Fast host discovery using ARP requests
- **ICMP Scanning**: Ping-based host discovery
- **TCP SYN Scanning**: Stealth port scanning
- **Service Detection**: Banner grabbing and service identification

### Passive Discovery
- **Traffic Monitoring**: Captures and analyzes network packets
- **Host Identification**: Discovers hosts from observed traffic
- **Service Detection**: Identifies services from passive monitoring

### mDNS Discovery
- **Service Enumeration**: Discovers advertised services
- **Device Identification**: Identifies devices by their mDNS announcements
- **Network Mapping**: Maps service relationships

## 📈 Performance

- **Concurrent Scanning**: Multi-threaded scanning for improved performance
- **Efficient Packet Capture**: Optimized packet processing
- **Memory Management**: Efficient handling of large network ranges
- **Result Caching**: Avoids redundant scans

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

**Permission Denied Errors**
- Ensure you're running with root/administrator privileges
- Check that your user has access to network interfaces

**No Hosts Discovered**
- Verify network interface selection
- Check network connectivity
- Ensure the target network range is correct

**API Connection Issues**
- Verify the API server is running on the correct port
- Check firewall settings
- Ensure `results.json` exists and is readable

**Credential Testing Failures**
- Verify the credential testing server is running
- Check network connectivity to target services
- Ensure proper service detection

### Debug Mode

Enable verbose logging by modifying the log levels in the respective Go files.

## 📞 Support

For issues, questions, or contributions, please:
1. Check the troubleshooting section
2. Review existing issues
3. Create a new issue with detailed information
4. Include system information and error logs

---

**RedMantis v2** - Comprehensive network discovery and asset management for modern networks.
