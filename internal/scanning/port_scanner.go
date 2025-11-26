package scanning

import (
	"fmt"
	"net"
	"sync"
	"time"

	"redmantis/internal/assets"
)

var CommonPorts = getDeduplicatedPorts()

func getDeduplicatedPorts() []int {

	allPorts := []int{
		22,   // SSH
		23,   // Telnet
		3389, // RDP
		5900, // VNC
		5901, // VNC-1
		5985, // WinRM HTTP
		5986, // WinRM HTTPS

		80,   // HTTP
		443,  // HTTPS
		8000, // HTTP-alt
		8008, // HTTP-alt
		8080, // HTTP-proxy
		8081, // HTTP-alt
		8088, // HTTP-alt
		8443, // HTTPS-alt
		8888, // HTTP-alt
		9000, // HTTP-alt
		9090, // HTTP-alt

		// File Transfer
		20,  // FTP-data
		21,  // FTP
		69,  // TFTP
		115, // SFTP

		// Mail Services
		25,  // SMTP
		110, // POP3
		143, // IMAP
		465, // SMTPS
		587, // SMTP submission
		993, // IMAPS
		995, // POP3S

		// Windows Services (Critical for Windows detection)
		135, // MSRPC
		137, // NetBIOS Name
		138, // NetBIOS Datagram
		139, // NetBIOS Session
		445, // SMB/CIFS
		593, // HTTP RPC Ep Map

		// Apple/macOS Services
		88,   // Kerberos
		548,  // AFP
		3689, // DAAP (iTunes)
		5353, // mDNS/Bonjour

		// Databases (Critical)
		1433,  // MSSQL
		1434,  // MSSQL Monitor
		1521,  // Oracle
		3050,  // Firebird/InterBase
		3306,  // MySQL/MariaDB
		5432,  // PostgreSQL
		5984,  // CouchDB
		6379,  // Redis
		7000,  // Cassandra Inter-node
		7001,  // Cassandra JMX
		7199,  // Cassandra JMX
		8086,  // InfluxDB
		9042,  // Cassandra CQL
		9200,  // Elasticsearch HTTP
		9300,  // Elasticsearch Transport
		27017, // MongoDB
		27018, // MongoDB shard
		28017, // MongoDB web

		// Directory Services
		88,   // Kerberos
		389,  // LDAP
		636,  // LDAPS
		3268, // LDAP Global Catalog
		3269, // LDAP Global Catalog SSL

		// Web Application Servers
		8009, // Apache JServ Protocol
		8180, // Apache Tomcat
		9080, // WebSphere
		9443, // WebSphere HTTPS

		// Messaging & Queue
		1883,  // MQTT
		4369,  // Erlang Port Mapper (RabbitMQ)
		5222,  // XMPP
		5269,  // XMPP Server
		5672,  // AMQP (RabbitMQ)
		6667,  // IRC
		8883,  // MQTT SSL
		9092,  // Kafka
		15672, // RabbitMQ Management
		61613, // STOMP
		61614, // STOMP SSL
		61616, // ActiveMQ

		// Network Services
		53,  // DNS
		67,  // DHCP Server
		68,  // DHCP Client
		123, // NTP
		161, // SNMP
		162, // SNMP Trap
		514, // Syslog

		// File Sharing
		111,  // RPC
		2049, // NFS
		2121, // FTP Proxy

		// Monitoring & Management
		161,   // SNMP
		9090,  // Prometheus
		9100,  // Prometheus Node Exporter
		9115,  // Prometheus Blackbox
		10050, // Zabbix Agent
		10051, // Zabbix Server

		// Container & Orchestration
		2375,  // Docker
		2376,  // Docker TLS
		2377,  // Docker Swarm
		4243,  // Docker
		6443,  // Kubernetes API
		8001,  // Kubernetes API Proxy
		9443,  // Portainer
		10250, // Kubelet
		10255, // Kubelet Read-only
		10256, // Kube Proxy

		// Proxies & Load Balancers
		1080, // SOCKS
		3128, // Squid Proxy
		8118, // Privoxy
		9999, // HAProxy Stats

		// Caching
		11211, // Memcached
		11212, // Memcached SSL

		// Search & Analytics
		9200, // Elasticsearch
		9300, // Elasticsearch
		5601, // Kibana

		// VPN & Security
		500,  // IKE/IPSec
		1194, // OpenVPN
		1723, // PPTP
		4500, // IPSec NAT-T

		// Virtualization
		902,  // VMware
		903,  // VMware
		5000, // Docker Registry

		// Big Data & Analytics
		8020,  // Hadoop NameNode
		8088,  // Hadoop YARN
		9000,  // Hadoop NameNode
		9083,  // Hive Metastore
		10000, // Hive Server
		16000, // HBase Master
		16020, // HBase Region
		50000, // SAP
		50070, // Hadoop NameNode Web

		// IoT & Smart Home
		1883, // MQTT
		5683, // CoAP
		8123, // Home Assistant
		8883, // MQTT SSL

		// Printers
		515,  // LPD/LPR
		631,  // IPP/CUPS
		9100, // Raw Printing

		// Gaming
		25565, // Minecraft
		27015, // Steam/Source
		27016, // Steam/Source

		// Backup & Storage
		3260,  // iSCSI
		10000, // Webmin
		10001, // Webmin SSL

		// Development
		3000, // Node.js/React dev
		4200, // Angular dev
		5000, // Flask dev
		8000, // Django dev
		9418, // Git

		// Additional Common Services
		179,   // BGP
		502,   // Modbus
		554,   // RTSP
		1900,  // UPnP
		2181,  // Zookeeper
		2222,  // DirectAdmin
		2379,  // etcd
		2380,  // etcd
		3000,  // Node.js
		4040,  // Riak
		4444,  // Metasploit
		5000,  // Various
		5001,  // Synology DSM
		5555,  // Android ADB
		6000,  // X11
		6001,  // X11-1
		7001,  // WebLogic
		7002,  // WebLogic SSL
		7474,  // Neo4j
		8069,  // Odoo
		8082,  // Blackboard
		8161,  // ActiveMQ Admin
		8500,  // Consul
		8600,  // Consul DNS
		9000,  // SonarQube
		9001,  // Tor
		9091,  // Transmission
		9200,  // Elasticsearch
		9418,  // Git
		11211, // Memcached
	}

	// Deduplicate ports using a map
	portMap := make(map[int]bool)
	var uniquePorts []int

	for _, port := range allPorts {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

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
