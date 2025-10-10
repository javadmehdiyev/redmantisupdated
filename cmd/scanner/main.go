package main

import (
	"fmt"
	"os"

	"redmantis/internal/config"
	"redmantis/internal/discovery"
)

func main() {
	// Load configuration
	cfg, err := config.Load("config.json")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		fmt.Println("Please ensure config.json exists and is properly formatted")
		os.Exit(1)
	}

	// Create and run orchestrator
	orchestrator := discovery.NewOrchestrator(cfg)
	orchestrator.Run()
}
