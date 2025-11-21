package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"redmantis/internal/config"
	"redmantis/internal/discovery"
)

func main() {
	allLogs := loadLogs()
	logData := LogEntry{
		StartTime: time.Now().Format(time.RFC3339),
		Messages:  []string{},
	}
	// Multi writer → console only (we'll save to JSON at the end)
	capture := &MultiWriter{
		file:     nil, // Don't write to file directly
		console:  os.Stdout,
		logStore: &logData.Messages,
	}

	// Redirect log package to capture logs
	log.SetOutput(capture)

	log.Println("============================")
	log.Println("=== Program started ===")

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

	log.Println("=== Program finished ===")
	log.Println("============================")

	// Finish logs
	logData.EndTime = time.Now().Format(time.RFC3339)

	// Add new log to the beginning of the array
	allLogs = append([]LogEntry{logData}, allLogs...)

	// Keep only last 15 logs
	if len(allLogs) > 15 {
		allLogs = allLogs[:15]
	}

	saveLogs(allLogs)

	log.Println("Logs saved -> scan_logs.json")
}

type LogEntry struct {
	StartTime string   `json:"start_time"`
	EndTime   string   `json:"end_time"`
	Messages  []string `json:"messages"`
}

type MultiWriter struct {
	file     io.Writer
	console  io.Writer
	logStore *[]string
}

func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	*mw.logStore = append(*mw.logStore, msg)

	mw.console.Write(p)
	if mw.file != nil {
		mw.file.Write(p)
	}

	return len(p), nil
}

// LogMessage manually logs a message (for cases where fmt.Printf/fmt.Println are used)
func (mw *MultiWriter) LogMessage(msg string) {
	// Ensure message ends with newline
	if len(msg) > 0 && msg[len(msg)-1] != '\n' {
		msg += "\n"
	}

	*mw.logStore = append(*mw.logStore, msg)
	mw.console.Write([]byte(msg))
	if mw.file != nil {
		mw.file.Write([]byte(msg))
	}
}

// loadLogs loads existing logs from file, returns empty slice if file doesn't exist or is invalid
func loadLogs() []LogEntry {
	data, err := os.ReadFile("scan_logs.json")
	if err != nil {
		// File doesn't exist or can't be read, return empty slice
		return []LogEntry{}
	}

	var logs []LogEntry
	if err := json.Unmarshal(data, &logs); err != nil {
		// Try to parse as single entry (old format)
		var singleEntry LogEntry
		if err2 := json.Unmarshal(data, &singleEntry); err2 == nil {
			return []LogEntry{singleEntry}
		}
		// Invalid JSON, return empty slice
		return []LogEntry{}
	}

	return logs
}

// saveLogs saves logs array to file
func saveLogs(logs []LogEntry) {
	file, err := os.OpenFile("scan_logs.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("ERROR: Cannot save scan_logs.json: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty print with 2 spaces
	if err := encoder.Encode(logs); err != nil {
		log.Printf("ERROR: Cannot encode logs: %v\n", err)
	}
}
