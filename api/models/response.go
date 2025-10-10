package models

import (
	"time"

	"redmantis/internal/assets"
)

// AssetResponse represents an asset in API responses
type AssetResponse struct {
	Address         string                  `json:"address" example:"10.1.1.13" description:"IP address of the asset"`
	Hostname        string                  `json:"hostname" example:"cavads-MacBook-Pro.local." description:"Hostname of the asset"`
	Os              string                  `json:"os" example:"unknown" description:"Operating system of the asset"`
	Type            string                  `json:"type" example:"unknown" description:"Type of the asset"`
	Hardware        string                  `json:"hardware" example:"unknown" description:"Hardware information of the asset"`
	MacVendor       string                  `json:"mac_vendor" example:"unknown" description:"MAC address vendor"`
	Mac             string                  `json:"mac" example:"e2:0f:5c:18:7f:af" description:"MAC address of the asset"`
	Screenshot      string                  `json:"screenshot" example:"" description:"Screenshot URL or path"`
	Date            time.Time               `json:"date" example:"2025-09-26T11:24:47.994799+04:00" description:"Discovery date"`
	Ports           []assets.PortScanResult `json:"ports" description:"List of open ports and services"`
	CredentialTests []assets.CredentialTest `json:"credential_tests" description:"List of credential tests performed"`
}

// AssetListResponse represents a paginated list of assets
type AssetListResponse struct {
	TotalAssets int             `json:"total_assets" example:"21" description:"Total number of assets"`
	CurrentPage int             `json:"current_page" example:"1" description:"Current page number"`
	PageSize    int             `json:"page_size" example:"10" description:"Number of assets per page"`
	TotalPages  int             `json:"total_pages" example:"3" description:"Total number of pages"`
	Data        []AssetResponse `json:"data" description:"List of assets for the current page"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Message string `json:"message" example:"Asset not found" description:"Error message"`
}

// ConvertAsset converts internal Asset to API AssetResponse
func ConvertAsset(asset assets.Asset) AssetResponse {
	return AssetResponse{
		Address:         asset.Address,
		Hostname:        asset.Hostname,
		Os:              asset.OS,
		Type:            asset.Type,
		Hardware:        asset.Hardware,
		MacVendor:       asset.MacVendor,
		Mac:             asset.Mac,
		Screenshot:      "", // Always empty as per original
		Date:            asset.Date,
		Ports:           asset.Ports,
		CredentialTests: asset.CredTest,
	}
}

// ConvertAssets converts slice of internal Assets to API AssetResponses
func ConvertAssets(assetList []assets.Asset) []AssetResponse {
	responses := make([]AssetResponse, len(assetList))
	for i, asset := range assetList {
		responses[i] = ConvertAsset(asset)
	}
	return responses
}
