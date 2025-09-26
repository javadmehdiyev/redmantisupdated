package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MacLookupResponse represents the API response from maclookup.app
type MacLookupResponse struct {
	Success    bool   `json:"success"`
	Found      bool   `json:"found"`
	MacPrefix  string `json:"macPrefix"`
	Company    string `json:"company"`
	Address    string `json:"address"`
	Country    string `json:"country"`
	BlockStart string `json:"blockStart"`
	BlockEnd   string `json:"blockEnd"`
	BlockSize  int    `json:"blockSize"`
	BlockType  string `json:"blockType"`
	Updated    string `json:"updated"`
	IsRand     bool   `json:"isRand"`
	IsPrivate  bool   `json:"isPrivate"`
	Error      string `json:"error,omitempty"`
	ErrorCode  int    `json:"errorCode,omitempty"`
}

// MacLookupClient handles MAC address vendor lookups
type MacLookupClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	cache      map[string]MacLookupResponse // Cache for OUI lookups
	cacheMutex sync.RWMutex
	rateLimiter chan struct{} // Simple rate limiting
}

// NewMacLookupClient creates a new MAC lookup client
func NewMacLookupClient(apiKey string) *MacLookupClient {
	client := &MacLookupClient{
		baseURL:     "https://api.maclookup.app/v2/macs",
		apiKey:      apiKey,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		cache:       make(map[string]MacLookupResponse),
		rateLimiter: make(chan struct{}, 5), // Max 5 concurrent requests
	}
	
	// Initialize rate limiter
	for i := 0; i < 5; i++ {
		client.rateLimiter <- struct{}{}
	}
	
	// Rate limiter refill goroutine (5 requests per second)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		
		for range ticker.C {
			select {
			case client.rateLimiter <- struct{}{}:
			default:
				// Channel is full, skip
			}
		}
	}()
	
	return client
}

// LookupMAC performs a MAC address lookup and returns vendor information
func (client *MacLookupClient) LookupMAC(macAddress string) (*MacLookupResponse, error) {
	if macAddress == "" || macAddress == "unknown" {
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "unknown",
		}, nil
	}

	// Extract OUI (first 6 characters) for caching
	oui := client.extractOUI(macAddress)
	if oui == "" {
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "unknown",
		}, fmt.Errorf("invalid MAC address format")
	}

	// Check cache first
	client.cacheMutex.RLock()
	if cached, exists := client.cache[oui]; exists {
		client.cacheMutex.RUnlock()
		return &cached, nil
	}
	client.cacheMutex.RUnlock()

	// Rate limiting
	<-client.rateLimiter

	// Build URL
	url := fmt.Sprintf("%s/%s", client.baseURL, oui)
	if client.apiKey != "" {
		url += "?apiKey=" + client.apiKey
	}

	// Make HTTP request
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "lookup_failed",
		}, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "lookup_failed",
		}, err
	}

	// Parse JSON response
	var result MacLookupResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "parse_failed",
		}, err
	}

	// Handle API errors
	if !result.Success {
		if result.ErrorCode == 429 {
			// Too many requests
			return &MacLookupResponse{
				Success: false,
				Found:   false,
				Company: "rate_limited",
			}, fmt.Errorf("rate limited")
		}
		return &MacLookupResponse{
			Success: false,
			Found:   false,
			Company: "api_error",
		}, fmt.Errorf("API error: %s", result.Error)
	}

	// Cache the result (cache by OUI)
	client.cacheMutex.Lock()
	client.cache[oui] = result
	client.cacheMutex.Unlock()

	return &result, nil
}

// LookupMultipleMACs performs bulk MAC address lookups with concurrency control
func (client *MacLookupClient) LookupMultipleMACs(macAddresses []string) map[string]*MacLookupResponse {
	results := make(map[string]*MacLookupResponse)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent lookups
	semaphore := make(chan struct{}, 3) // Max 3 concurrent API calls

	for _, mac := range macAddresses {
		if mac == "" || mac == "unknown" {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(macAddr string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result, err := client.LookupMAC(macAddr)
			if err != nil {
				// Create error result
				result = &MacLookupResponse{
					Success: false,
					Found:   false,
					Company: "lookup_error",
				}
			}

			mu.Lock()
			results[macAddr] = result
			mu.Unlock()
		}(mac)
	}

	wg.Wait()
	return results
}

// extractOUI extracts the OUI (first 6 hex characters) from a MAC address
func (client *MacLookupClient) extractOUI(macAddress string) string {
	// Remove separators
	cleaned := strings.ReplaceAll(macAddress, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")
	cleaned = strings.ToUpper(cleaned)

	// Validate length
	if len(cleaned) < 6 {
		return ""
	}

	// Return first 6 characters (OUI)
	return cleaned[:6]
}

// GetCacheStats returns cache statistics
func (client *MacLookupClient) GetCacheStats() (int, int) {
	client.cacheMutex.RLock()
	defer client.cacheMutex.RUnlock()
	
	cached := len(client.cache)
	hits := 0
	for _, result := range client.cache {
		if result.Found {
			hits++
		}
	}
	
	return cached, hits
}
