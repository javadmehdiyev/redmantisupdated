package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// NetworkInfo holds information about a network interface
type NetworkInfo struct {
	InterfaceName string
	IPAddress     string
	NetworkCIDR   string
	Subnet        string
	NetMask       string
}

// GetNetworkInterfaces returns a list of all active non-loopback network interfaces with IPv4 addresses
func GetNetworkInterfaces() ([]NetworkInfo, error) {
	var networkInfos []NetworkInfo

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback, inactive, or interfaces without addresses
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to get addresses for interface %s: %v\n", iface.Name, err)
			continue
		}

		// Process each address
		for _, addr := range addrs {
			// We're only interested in IP networks (not IP addresses)
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip IPv6 addresses
			if ipNet.IP.To4() == nil {
				continue
			}

			// Get IP and network information
			ip := ipNet.IP.To4().String()
			mask := ipNet.Mask

			// Calculate subnet
			// Convert IP to uint32 for bitwise operations
			ipUint := uint32(ipNet.IP.To4()[0])<<24 | uint32(ipNet.IP.To4()[1])<<16 | uint32(ipNet.IP.To4()[2])<<8 | uint32(ipNet.IP.To4()[3])
			// Convert mask to uint32
			maskUint := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
			// Calculate network address
			networkUint := ipUint & maskUint
			// Convert back to dotted decimal
			network := fmt.Sprintf("%d.%d.%d.%d",
				byte(networkUint>>24), byte(networkUint>>16), byte(networkUint>>8), byte(networkUint))

			// Calculate CIDR notation
			ones, _ := mask.Size()
			cidr := fmt.Sprintf("%s/%d", network, ones)

			// Format netmask as string
			netmaskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

			networkInfos = append(networkInfos, NetworkInfo{
				InterfaceName: iface.Name,
				IPAddress:     ip,
				NetworkCIDR:   cidr,
				Subnet:        network,
				NetMask:       netmaskStr,
			})
		}
	}

	if len(networkInfos) == 0 {
		return nil, fmt.Errorf("no suitable network interfaces found")
	}

	return networkInfos, nil
}

// GetPrimaryNetworkInterface tries to determine the primary network interface
// It uses heuristics like preferring en0/eth0/wlan0 and non-virtual interfaces
func GetPrimaryNetworkInterface(interfaces []NetworkInfo) NetworkInfo {
	if len(interfaces) == 0 {
		return NetworkInfo{}
	}

	// Common primary interface names
	primaryNames := []string{"en0", "eth0", "wlan0"}

	// First, try to find common primary interfaces
	for _, name := range primaryNames {
		for _, iface := range interfaces {
			if iface.InterfaceName == name {
				return iface
			}
		}
	}

	// Next, try to find interfaces that don't look virtual
	for _, iface := range interfaces {
		name := iface.InterfaceName
		if !strings.Contains(name, "virtual") &&
			!strings.Contains(name, "vbox") &&
			!strings.Contains(name, "vmnet") &&
			!strings.Contains(name, "docker") &&
			!strings.Contains(name, "veth") {
			return iface
		}
	}

	// If all else fails, return the first interface
	return interfaces[0]
}

// PrintNetworkInterfaces gets and prints all network interfaces
func PrintNetworkInterfaces() {
	// Get all network interfaces
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get the primary network interface
	primary := GetPrimaryNetworkInterface(interfaces)

	// Print all network interfaces
	fmt.Println("Available Network Interfaces:")
	fmt.Println("=============================")
	for i, iface := range interfaces {
		fmt.Printf("%d. Interface: %s\n", i+1, iface.InterfaceName)
		fmt.Printf("   IP Address: %s\n", iface.IPAddress)
		fmt.Printf("   Network CIDR: %s\n", iface.NetworkCIDR)
		fmt.Printf("   Subnet: %s\n", iface.Subnet)
		fmt.Printf("   Netmask: %s\n", iface.NetMask)
		fmt.Println()
	}

	// Print the primary interface
	fmt.Println("Primary Network Interface:")
	fmt.Println("==========================")
	fmt.Printf("Interface: %s\n", primary.InterfaceName)
	fmt.Printf("IP Address: %s\n", primary.IPAddress)
	fmt.Printf("Network CIDR: %s\n", primary.NetworkCIDR)
	fmt.Printf("Subnet: %s\n", primary.Subnet)
	fmt.Printf("Netmask: %s\n", primary.NetMask)
	fmt.Println()
}
