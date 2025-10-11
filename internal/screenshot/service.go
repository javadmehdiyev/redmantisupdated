package screenshot

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/chromedp/chromedp"

	"redmantis/internal/assets"
)

// Service handles web screenshot capture
type Service struct {
	timeout    time.Duration
	maxWorkers int
}

// NewService creates a new screenshot service
func NewService(timeout time.Duration, maxWorkers int) *Service {
	return &Service{
		timeout:    timeout,
		maxWorkers: maxWorkers,
	}
}

// CaptureScreenshots captures screenshots for all assets with web services
func (s *Service) CaptureScreenshots(assetList []assets.Asset) []assets.Asset {
	fmt.Println("\n=== Phase: Screenshot Capture ===")
	fmt.Printf("Capturing screenshots for web services (timeout: %v, workers: %d)...\n", s.timeout, s.maxWorkers)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]assets.Asset, len(assetList))
		sem     = make(chan struct{}, s.maxWorkers)
	)

	// Copy assets to results
	copy(results, assetList)

	screenshotCount := 0
	for i, asset := range results {
		// Check if asset has web services
		webURLs := s.identifyWebServices(asset)
		if len(webURLs) == 0 {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(idx int, urls []string, ip string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			// Try to capture screenshot from any of the web services
			for _, url := range urls {
				screenshot, err := s.captureScreenshot(url)
				if err != nil {
					log.Printf("Failed to capture screenshot for %s: %v", url, err)
					continue
				}

				if screenshot != "" {
					mu.Lock()
					results[idx].Screenshot = screenshot
					screenshotCount++
					mu.Unlock()
					fmt.Printf("✓ Captured screenshot for %s (%s)\n", ip, url)
					break // Successfully captured, no need to try other URLs
				}
			}
		}(i, webURLs, asset.Address)
	}

	wg.Wait()
	fmt.Printf("Screenshot capture completed: %d screenshots captured\n", screenshotCount)

	return results
}

// identifyWebServices identifies web service URLs from an asset's open ports
func (s *Service) identifyWebServices(asset assets.Asset) []string {
	var urls []string
	webPorts := map[int]string{
		80:   "http",
		443:  "https",
		8080: "http",
		8443: "https",
		8000: "http",
		8888: "http",
		3000: "http",
		5000: "http",
		5900: "http",
		7000: "http",
		7001: "http",
		9000: "http",
		9090: "http",
	}

	for _, port := range asset.Ports {
		if port.State != "open" {
			continue
		}

		// Check if it's a known web port
		if protocol, ok := webPorts[port.Number]; ok {
			url := fmt.Sprintf("%s://%s:%d", protocol, asset.Address, port.Number)
			urls = append(urls, url)
			continue
		}

		// Check service name for HTTP indicators
		serviceLower := port.Service
		if serviceLower == "" {
			serviceLower = port.Banner
		}

		if containsAny(serviceLower, []string{"http", "web", "nginx", "apache", "tomcat", "jetty", "express", "nodejs"}) {
			// Default to http, use https for higher ports or if service mentions ssl/tls
			protocol := "http"
			if port.Number > 8000 || containsAny(serviceLower, []string{"https", "ssl", "tls"}) {
				protocol = "https"
			}
			url := fmt.Sprintf("%s://%s:%d", protocol, asset.Address, port.Number)
			urls = append(urls, url)
		}
	}

	return urls
}

// captureScreenshot captures a screenshot of a web page and returns it as base64
func (s *Service) captureScreenshot(url string) (string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Create chromedp context with options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "IsolateOrigins,site-per-process"),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	// Create browser context
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	// Capture screenshot
	var buf []byte
	err := chromedp.Run(browserCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Wait for page to load
		chromedp.CaptureScreenshot(&buf),
	)

	if err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Convert to base64
	base64String := base64.StdEncoding.EncodeToString(buf)
	return base64String, nil
}

// containsAny checks if a string contains any of the substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) && contains(s, substr) {
			return true
		}
	}
	return false
}

// contains is a simple case-insensitive contains check
func contains(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// toLower converts string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}
