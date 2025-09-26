package main

import (
	"fmt"
	"math"
	"net"
	"os"
)

// Host represents a network host with its IP address
type Host struct {
	IPAddress string
}

// GetAllHostsInNetwork returns all valid host IP addresses in the given CIDR network
// It excludes the network address and broadcast address
func GetAllHostsInNetwork(networkCIDR string) ([]Host, error) {
	// Parse the CIDR notation
	_, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR %s: %w", networkCIDR, err)
	}

	// Get the IP and mask
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("not an IPv4 network: %s", networkCIDR)
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()

	// Calculate the number of hosts
	// For a /24 network, this would be 2^(32-24) = 2^8 = 256
	// We subtract 2 to exclude network and broadcast addresses
	numHosts := int(math.Pow(2, float64(bits-ones))) - 2
	if numHosts <= 0 {
		// Handle special cases like /31 and /32 networks
		if ones == 31 {
			// RFC 3021 allows /31 networks to have 2 hosts (no network/broadcast)
			numHosts = 2
		} else if ones == 32 {
			// /32 networks have only 1 host
			numHosts = 1
		} else {
			return nil, fmt.Errorf("network %s does not have usable host addresses", networkCIDR)
		}
	}

	// Convert IP to uint32 for easier manipulation
	ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	// Get the network address
	networkUint := ipUint & (uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3]))

	hosts := make([]Host, 0, numHosts)

	// Start from the first host (network address + 1)
	// Unless it's a /31 or /32 network
	startHost := networkUint + 1
	endHost := networkUint + uint32(math.Pow(2, float64(bits-ones))) - 2

	if ones == 31 {
		// For /31, use both addresses as hosts (RFC 3021)
		startHost = networkUint
		endHost = networkUint + 1
	} else if ones == 32 {
		// For /32, use the single address
		startHost = networkUint
		endHost = networkUint
	}

	// Generate all host IP addresses
	for hostUint := startHost; hostUint <= endHost; hostUint++ {
		hostIP := fmt.Sprintf("%d.%d.%d.%d",
			byte(hostUint>>24), byte(hostUint>>16), byte(hostUint>>8), byte(hostUint))
		hosts = append(hosts, Host{IPAddress: hostIP})
	}

	return hosts, nil
}

// PrintAllHostsInNetwork gets all hosts in the primary network and prints them
func PrintAllHostsInNetwork() {
	// Get all network interfaces
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get the primary network interface
	primary := GetPrimaryNetworkInterface(interfaces)
	fmt.Printf("Using network: %s\n", primary.NetworkCIDR)

	// Get all hosts in the primary network
	hosts, err := GetAllHostsInNetwork(primary.NetworkCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting hosts: %v\n", err)
		os.Exit(1)
	}

	// Print all hosts
	fmt.Printf("Found %d host addresses in network %s\n", len(hosts), primary.NetworkCIDR)
	fmt.Println("Host IP Addresses:")
	fmt.Println("==================")

	// Print the first 10 and last 10 hosts if there are more than 20 hosts
	if len(hosts) > 20 {
		for i := 0; i < 10; i++ {
			fmt.Printf("%d. %s\n", i+1, hosts[i].IPAddress)
		}
		fmt.Println("...")
		for i := len(hosts) - 10; i < len(hosts); i++ {
			fmt.Printf("%d. %s\n", i+1, hosts[i].IPAddress)
		}
		fmt.Printf("\nShowing 20 of %d hosts. The list is too large to display in full.\n", len(hosts))
	} else {
		// Print all hosts if there are 20 or fewer
		for i, host := range hosts {
			fmt.Printf("%d. %s\n", i+1, host.IPAddress)
		}
	}
}
