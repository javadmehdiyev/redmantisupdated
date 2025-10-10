# RedMantis v2 - Network Discovery Tool

Fast network scanner with asset discovery, credential testing, and REST API.

## ⚡ Quick Start

### Prerequisites
- Go 1.25+ 
- Python 3.7+ 
- nmap
- Root/sudo access

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

### Credential Testing (Optional)
```bash
cd credtestserver
pip install -r requirements.txt
python app.py
```

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
  "port_scan": { "enabled": true }
}
```

## 📋 Features

- **Multi-technique Discovery**: ARP, ICMP, TCP, SYN, Passive, mDNS, NetBIOS
- **Windows Detection**: NetBIOS queries for hostname and OS info
- **Port & Service Scanning**: nmap integration with banner grabbing  
- **Credential Testing**: Default password testing on discovered services
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

=== Phase 8: Credential Testing ===
✓ Found vulnerable credentials for 192.168.1.100:22 - admin:admin (SSH)
```

**JSON Export (`assets.json`):**
```json
[{
  "address": "192.168.1.100",
  "hostname": "WIN10-PC", 
  "os": "Windows 10",
  "ports": [{"number": 22, "service": "OpenSSH 8.2"}],
  "credential_tests": [{"service": "ssh", "success": true}]
}]
```

## 🛡️ Security Notice

- Use only on networks you own/authorize
- Generates network traffic - use responsibly  
- Tests default credentials - ensure proper authorization

---

**Quick, comprehensive network asset discovery made simple.**
