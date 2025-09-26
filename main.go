package main

import (
	"fmt"
)

func main() {
	// Print header
	fmt.Println("RedMantis v2 - Network Scanner")
	fmt.Println("==============================")
	fmt.Println()

	// Perform ARP scan to get MAC addresses and alive status
	ScanHosts()
}