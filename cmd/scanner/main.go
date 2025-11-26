package main

import (
	"log"
	"os"

	"redmantis/internal/config"
	"redmantis/internal/discovery"
)

func main() {
	logData, capture, allLogs := initLogging()

	// Load configuration
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("Error loading config: %v\n", err)
		log.Println("Please ensure config.json exists and is properly formatted")
		os.Exit(1)
	}

	// Create and run orchestrator with manual logger
	orchestrator := discovery.NewOrchestrator(cfg, capture.LogMessage)
	orchestrator.Run()

	finalizeLogging(logData, allLogs)
}
