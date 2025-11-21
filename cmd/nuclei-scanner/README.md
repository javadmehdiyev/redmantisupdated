# RedMantis Nuclei Scanner

A separate module for vulnerability scanning using Nuclei based on RedMantis results.

## Description

This module:
- ✅ Reads `assets.json` (RedMantis results)
- ✅ Extracts web services (HTTP/HTTPS)
- ✅ Runs Nuclei scanning
- ✅ Merges results with original assets
- ✅ Saves to `nuclei_assets.json` (does not modify `assets.json`)

## Requirements

1. **Nuclei must be installed**:
   ```bash
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   nuclei -update-templates
   ```

2. **File `assets.json`** must exist (created by RedMantis scanner)

## Usage

### Building

```bash
cd cmd/nuclei-scanner
go build -o nuclei-scanner .
```

Or from the project root:

```bash
go build -o nuclei-scanner ./cmd/nuclei-scanner
```

### Running

```bash
./nuclei-scanner
```

Or from the project root:

```bash
./nuclei-scanner
```

## Configuration

The module uses settings from `config.json`:

```json
{
  "nuclei": {
    "enabled": true,
    "severity": ["critical", "high", "medium"],
    "rate_limit": 10,
    "concurrency": 25,
    "timeout": "30s"
  }
}
```

**Important**: If `nuclei.enabled` is set to `false`, the module will exit with a message.

## Output

Results are saved to `nuclei_assets.json` in the following format:

```json
[
  {
    "address": "192.168.1.100",
    "hostname": "example.local",
    "ports": [...],
    "nuclei_vulnerabilities": [
      {
        "template-id": "CVE-2021-44228",
        "matched-at": "http://192.168.1.100:8080",
        "info": {
          "name": "Log4j RCE",
          "severity": "critical",
          "tags": ["cve", "rce"]
        }
      }
    ]
  }
]
```

## Usage Example

```bash
# 1. Run RedMantis scanner
sudo ./redmantis

# 2. Run Nuclei scanner
./nuclei-scanner

# 3. View results
cat nuclei_assets.json | jq '.[] | select(.nuclei_vulnerabilities != null)'
```

## Statistics

After scanning completes, the module outputs:
- Total number of assets
- Number of assets with vulnerabilities
- Total number of vulnerabilities found
- Distribution by severity levels

## Notes

- The module **does not modify** the original `assets.json` file
- Nuclei results are added to a new field `nuclei_vulnerabilities`
- If an asset has no vulnerabilities, the `nuclei_vulnerabilities` field will be absent (or empty)
