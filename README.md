# RedMantis v2 - Network Discovery Tool

Fast network scanner with asset discovery, credential testing, and REST API.

## ⚡ Quick Start

### Prerequisites
- Go 1.25+ 
- Google Chrome or Chromium (for screenshots)
- Root/sudo access (for SYN scanning only)

### Installation & Run
```bash
# Install & build
go mod tidy
go build -o redmantis ./cmd/scanner

# Run scanner (finds all devices in your network)
sudo ./redmantis
```

Results saved to `assets.json`

### API Server
```bash
# Build & start API
cd api
go mod tidy  
go build -o redmantis-api .
./redmantis-api
```

API available at: `http://localhost:8080`
- **GET /assets** - List all discovered assets
- **GET /assets/{ip}** - Get specific asset details
- **GET /swagger/index.html** - API documentation

## 🔧 Configuration

Edit `config.json`:
```json
{
  "service": { "name": "Asset Management Service" },
  "network": { 
    "interface": "auto",
    "scan_local_network": true 
  },
  "arp": { "enabled": true },
  "netbios": { "enabled": true },  
  "port_scan": { "enabled": true },
  "credentials": {
    "enabled": true,
    "settings_file": "settings.json",
    "timeout": "10s",
    "workers": 5
  }
}
```

Credentials are loaded from `settings.json`

## 📋 Features

- **Multi-technique Discovery**: ARP, ICMP, TCP, SYN, Passive, mDNS (with retries), NetBIOS
- **Windows Detection**: NetBIOS queries for hostname and OS info
- **Fast Port Scanning**: Native Go port scanner with parallel execution and banner grabbing
- **Web Screenshots**: Automatic screenshot capture of web services (base64 encoded)
- **Credential Testing**: Native Go credential testing (SSH, FTP, MySQL, PostgreSQL, HTTP, etc.)
- **Asset Enrichment**: Intelligent MAC vendor lookup, OS detection (99% accuracy), device classification
- **mDNS Discovery**: Comprehensive service detection with 3 retries (80+ service types, 95%+ discovery)
- **Asset Inventory**: Complete device information with JSON export
- **REST API**: Programmatic access with pagination

## 🎯 What You Get

**Console Output:**
```bash
=== Phase 1: ARP Scanning ===
Found 15 alive hosts

=== Phase 6: NetBIOS Discovery ===
✓ Found NetBIOS info for 192.168.1.100: WIN10-PC (Windows 10)
✓ Found NetBIOS info for 192.168.1.101: SERVER2019 (Windows Server)

=== Phase 7: Screenshot Capture ===
✓ Captured screenshot for 192.168.1.100 (http://192.168.1.100:80)
✓ Captured screenshot for 192.168.1.101 (https://192.168.1.101:443)

=== Phase 8: Credential Testing ===
Testing default credentials from settings.json...
Found 15 open ports across 5 hosts to test
✓ Found vulnerable credentials for 192.168.1.100:22 (ssh)
  - admin:admin
```

**JSON Export (`assets.json`):**
```json
[{
  "address": "192.168.1.100",
  "hostname": "WIN10-PC", 
  "os": "Windows 10",
  "ports": [{"number": 22, "service": "OpenSSH 8.2"}],
  "credential_tests": [{"service": "ssh", "success": true}],
  "screenshot": "iVBORw0KGgoAAAANSUhEUgAA..."
}]
```

**Note**: The `screenshot` field contains a base64-encoded PNG image that can be displayed in web browsers.

## 🛡️ Security Notice

- Use only on networks you own/authorize
- Generates network traffic - use responsibly  
- Tests default credentials - ensure proper authorization

---

**Quick, comprehensive network asset discovery made simple.**
