package assets

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MACVendorCache stores MAC vendor lookups to avoid repeated API calls
var (
	macVendorCache      = make(map[string]string)
	macVendorCacheMutex sync.RWMutex
	lastAPICall         time.Time
	apiCallMutex        sync.Mutex
)

// LookupMACVendor queries the macvendors.com API to get vendor information for a MAC address
func LookupMACVendor(macAddress string) string {
	if macAddress == "" || macAddress == "unknown" {
		return "Unknown Vendor"
	}

	// Normalize MAC address
	mac := strings.ToUpper(strings.ReplaceAll(macAddress, "-", ":"))

	// Check cache first
	macVendorCacheMutex.RLock()
	if vendor, found := macVendorCache[mac]; found {
		macVendorCacheMutex.RUnlock()
		return vendor
	}
	macVendorCacheMutex.RUnlock()

	// Rate limiting: wait at least 1 second between API calls (free tier limit)
	apiCallMutex.Lock()
	timeSinceLastCall := time.Since(lastAPICall)
	if timeSinceLastCall < time.Second {
		time.Sleep(time.Second - timeSinceLastCall)
	}
	lastAPICall = time.Now()
	apiCallMutex.Unlock()

	// Query API
	vendor := queryMACVendorAPI(mac)

	// Cache the result
	macVendorCacheMutex.Lock()
	macVendorCache[mac] = vendor
	macVendorCacheMutex.Unlock()

	return vendor
}

// queryMACVendorAPI makes the actual HTTP request to macvendors.com
func queryMACVendorAPI(mac string) string {
	// Use only the OUI part (first 3 octets) for lookup
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return "Unknown Vendor"
	}
	oui := strings.Join(parts[:3], ":")

	url := fmt.Sprintf("https://api.macvendors.com/%s", oui)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "Unknown Vendor"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "Unknown Vendor"
	}

	if resp.StatusCode != 200 {
		return "Unknown Vendor"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown Vendor"
	}

	vendor := strings.TrimSpace(string(body))
	if vendor == "" {
		return "Unknown Vendor"
	}

	return vendor
}

// LookupMACVendorsBatch performs batch lookups with rate limiting
func LookupMACVendorsBatch(macAddresses []string) map[string]string {
	results := make(map[string]string)

	for _, mac := range macAddresses {
		vendor := LookupMACVendor(mac)
		results[mac] = vendor
	}

	return results
}


