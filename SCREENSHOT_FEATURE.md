# Screenshot Feature Documentation

## Overview
The RedMantis scanner now includes automatic screenshot capture of web services discovered during network scanning. Screenshots are captured using a headless Chrome browser and stored as base64-encoded PNG images in the assets.json file.

## Features

### ✅ What Was Implemented

1. **Asset Model Update**
   - Added `screenshot` field to the `Asset` struct
   - Field is optional (`omitempty`) and stores base64-encoded PNG data

2. **Screenshot Service** (`internal/screenshot/service.go`)
   - Automatic detection of web services on common HTTP/HTTPS ports (80, 443, 8080, 8443, 3000, 5000, etc.)
   - Service name analysis to identify web servers (nginx, apache, express, etc.)
   - Headless Chrome browser integration via chromedp
   - Parallel screenshot capture with configurable workers
   - Automatic timeout handling (15 seconds default)
   - SSL/TLS certificate error handling

3. **Integration**
   - Seamlessly integrated into the orchestrator workflow (Phase 7)
   - Runs after credential testing, before final export
   - Non-blocking: failures don't stop the scanning process

4. **Screenshot Viewer**
   - Beautiful HTML5 viewer (`screenshot_viewer.html`)
   - Load and display screenshots from assets.json
   - Statistics dashboard
   - Full-screen image viewing
   - Responsive grid layout

## Usage

### Running the Scanner
```bash
# Build
go mod tidy
go build -o redmantis ./cmd/scanner/main.go

# Run (requires Chrome/Chromium installed)
sudo ./redmantis
```

### Viewing Screenshots

#### Option 1: HTML Viewer (Recommended)
```bash
# Open in browser
open screenshot_viewer.html
# or
firefox screenshot_viewer.html

# Then load the assets.json file via the file picker
```

#### Option 2: Programmatic Access
```python
import json
import base64

# Load assets
with open('assets.json', 'r') as f:
    assets = json.load(f)

# Extract screenshot
for asset in assets:
    if asset.get('screenshot'):
        # Decode base64 to image
        image_data = base64.b64decode(asset['screenshot'])
        
        # Save to file
        with open(f"{asset['address']}.png", 'wb') as img:
            img.write(image_data)
```

#### Option 3: Web Browser (Direct)
```html
<img src="data:image/png;base64,<BASE64_STRING_HERE>" />
```

## Configuration

### Service Configuration
The screenshot service is configured in the orchestrator:
```go
screenshotService := screenshot.NewService(
    15*time.Second,  // Timeout per screenshot
    5,               // Number of concurrent workers
)
```

### Detected Web Ports
The service automatically identifies web services on these ports:
- **80, 443**: Standard HTTP/HTTPS
- **8080, 8443**: Alternative HTTP/HTTPS
- **8000, 8888**: Development servers
- **3000**: Node.js/React dev servers
- **5000**: Flask/Python servers
- **5900, 7000, 7001, 9000, 9090**: Various web services

### Service Name Detection
Also detects web services by analyzing service banners for:
- http, https, web
- nginx, apache, tomcat, jetty
- express, nodejs
- ssl, tls (for protocol detection)

## Technical Details

### Dependencies
- **chromedp**: Chrome DevTools Protocol for Go
- **Google Chrome or Chromium**: Required for screenshot capture

### Architecture
```
Orchestrator (Phase 7)
    ↓
Screenshot Service
    ↓
identifyWebServices() → Scans ports for web services
    ↓
captureScreenshot() → Uses chromedp to capture
    ↓
base64 encode → Stores in Asset.Screenshot
    ↓
Export to assets.json
```

### Error Handling
- Timeouts: 15 seconds per screenshot
- SSL errors: Automatically ignored
- Missing Chrome: Logs error but continues scanning
- Failed captures: Logged but don't stop the process

## Output Example

### Console Output
```
=== Phase 7: Screenshot Capture ===
Capturing screenshots for web services (timeout: 15s, workers: 5)...
✓ Captured screenshot for 10.1.1.13 (http://10.1.1.13:5000)
✓ Captured screenshot for 185.111.245.42 (http://185.111.245.42:80)
✓ Captured screenshot for 185.111.245.42 (https://185.111.245.42:443)
Screenshot capture completed: 3 screenshots captured
```

### JSON Output
```json
{
  "address": "10.1.1.13",
  "hostname": "cavads-MacBook-Pro.local.",
  "ports": [
    {"number": 5000, "service": "rtsp", "state": "open"}
  ],
  "screenshot": "iVBORw0KGgoAAAANSUhEUgAAB4AAAAQ4CAYAAADo08FDAA..."
}
```

## Performance

### Benchmarks
- Screenshot capture: ~2-5 seconds per page
- Parallel workers: 5 concurrent screenshots
- Network with 10 web services: ~30-60 seconds total

### Resource Usage
- Memory: ~100-200MB per Chrome instance
- CPU: Moderate during capture, idle otherwise
- Network: Minimal (only loads target pages)

## Troubleshooting

### "Chrome not found" Error
```bash
# macOS
brew install --cask google-chrome

# Ubuntu/Debian
sudo apt-get install chromium-browser

# RHEL/CentOS
sudo yum install chromium
```

### Screenshots Not Capturing
1. Check Chrome/Chromium is installed
2. Verify firewall isn't blocking connections
3. Check target web service is actually responding
4. Increase timeout if needed (edit orchestrator.go)

### Base64 Too Large
Screenshots are compressed PNG images, typically 100KB-500KB each. For very large assets.json files:
- Consider implementing image compression
- Use external image storage
- Filter screenshots in post-processing

## Future Enhancements

Potential improvements:
- [ ] Configurable screenshot resolution
- [ ] Image compression/optimization
- [ ] Screenshot thumbnails
- [ ] Selective screenshot capture (only certain ports)
- [ ] Screenshot comparison (detect changes over time)
- [ ] OCR text extraction from screenshots
- [ ] Add screenshot configuration to config.json

## Security Considerations

- Screenshots may contain sensitive information
- Base64 data significantly increases assets.json file size
- Ensure proper access controls on assets.json
- Consider encrypting screenshots for sensitive environments

## License
Part of RedMantis Network Scanner

