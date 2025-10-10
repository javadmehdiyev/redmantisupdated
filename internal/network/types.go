package network

// NetworkInfo holds information about a network interface
type NetworkInfo struct {
	InterfaceName string
	IPAddress     string
	NetworkCIDR   string
	Subnet        string
	NetMask       string
}

// Host represents a network host with its IP address
type Host struct {
	IPAddress string
}

// HostStatus represents a host with its IP address, MAC address, and alive status
type HostStatus struct {
	IPAddress  string
	MACAddress string
	IsAlive    bool
}
