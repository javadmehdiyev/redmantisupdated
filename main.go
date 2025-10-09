package main

import (
	"fmt"
	"os"
)

func main() {
	// Print header
	fmt.Println("RedMantis v2 - Network Scanner")
	fmt.Println("==============================")
	fmt.Println()

	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		fmt.Println("Please ensure config.json exists and is properly formatted")
		os.Exit(1)
	}

	fmt.Printf("Loaded configuration for: %s\n", config.Service.Name)
	fmt.Printf("Network interface mode: %s\n", config.Network.Interface)
	if config.Network.AutoDetectLocal {
		fmt.Println("Auto-detecting local network configuration...")
	}
	fmt.Println()

	// Perform comprehensive network scanning using configuration
	ScanHosts(config)
}
