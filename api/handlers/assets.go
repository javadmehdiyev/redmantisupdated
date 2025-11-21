package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"redmantis/api/models"
	"redmantis/internal/assets"

	"github.com/gin-gonic/gin"
)

// AssetHandler handles asset-related API requests
type AssetHandler struct {
	assetList []assets.Asset
}

// NewAssetHandler creates a new asset handler
func NewAssetHandler() *AssetHandler {
	handler := &AssetHandler{}
	if err := handler.loadAssets(); err != nil {
		log.Fatal("Failed to load assets from results.json:", err)
	}
	return handler
}

// loadAssets loads assets data from the results.json file
func (h *AssetHandler) loadAssets() error {
	assetList, err := assets.LoadFromJSON("../assets.json")
	if err != nil {
		return err
	}

	// Set default screenshot value for assets that don't have it
	for i := range assetList {
		// Initialize empty slices if they are nil
		if assetList[i].Ports == nil {
			assetList[i].Ports = []assets.PortScanResult{}
		}
		if assetList[i].CredTest == nil {
			assetList[i].CredTest = []assets.CredentialTest{}
		}
	}

	h.assetList = assetList
	log.Printf("Successfully loaded %d assets from results.json", len(assetList))
	return nil
}

// GetAssets handles the GET /assets endpoint
// @Summary Get paginated list of assets
// @Description Retrieve a paginated list of all discovered network assets with optional filtering
// @Tags assets
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)" default(1)
// @Param size query int false "Number of assets per page (default: 10)" default(10)
// @Success 200 {object} models.AssetListResponse "Successfully retrieved assets"
// @Failure 400 {object} models.ErrorResponse "Invalid parameters"
// @Router /assets [get]
func (h *AssetHandler) GetAssets(c *gin.Context) {
	sizeParam := c.Query("size")
	pageParam := c.Query("page")

	var size int = 10 // default page size
	var page int = 1  // default page number
	var err error

	// Parse size parameter
	if sizeParam != "" {
		size, err = strconv.Atoi(sizeParam)
		if err != nil || size < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid size parameter"})
			return
		}
	}

	if pageParam != "" {
		page, err = strconv.Atoi(pageParam)
		if err != nil || page < 1 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid page parameter"})
			return
		}
	}

	totalAssets := len(h.assetList)
	totalPages := (totalAssets + size - 1) / size

	// Calculate offset
	offset := (page - 1) * size

	// Check page bounds
	if offset >= totalAssets && totalAssets > 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Page out of bounds"})
		return
	}

	// Calculate end index
	end := offset + size
	if end > totalAssets {
		end = totalAssets
	}

	// Get paginated data
	var paginatedData []assets.Asset
	if offset < totalAssets {
		paginatedData = h.assetList[offset:end]
	} else {
		paginatedData = []assets.Asset{}
	}

	response := models.AssetListResponse{
		TotalAssets: totalAssets,
		CurrentPage: page,
		PageSize:    size,
		TotalPages:  totalPages,
		Data:        models.ConvertAssets(paginatedData),
	}

	c.JSON(http.StatusOK, response)
}

func (h *AssetHandler) GetAssetLogs(c *gin.Context) {
	logsData, err := os.ReadFile("../scan_logs.json")
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "scan logs not found"})
		return
	}

	var logEntries []struct {
		StartTime string   `json:"start_time"`
		EndTime   string   `json:"end_time"`
		Messages  []string `json:"messages"`
	}

	// Try to parse as array first
	if err := json.Unmarshal(logsData, &logEntries); err != nil {
		// Try to parse as single entry (old format for backward compatibility)
		var singleEntry struct {
			StartTime string   `json:"start_time"`
			EndTime   string   `json:"end_time"`
			Messages  []string `json:"messages"`
		}
		if err2 := json.Unmarshal(logsData, &singleEntry); err2 != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Message: "failed to parse log file"})
			return
		}
		// Convert single entry to array
		logEntries = []struct {
			StartTime string   `json:"start_time"`
			EndTime   string   `json:"end_time"`
			Messages  []string `json:"messages"`
		}{singleEntry}
	}

	c.JSON(http.StatusOK, logEntries)
}

// GetAssetByIP handles the GET /assets/:ip endpoint
// @Summary Get asset by IP address
// @Description Retrieve detailed information about a specific network asset by its IP address
// @Tags assets
// @Accept json
// @Produce json
// @Param ip path string true "IP address of the asset" example(10.1.1.13)
// @Success 200 {object} models.AssetResponse "Successfully retrieved asset"
// @Failure 400 {object} models.ErrorResponse "Invalid IP address format"
// @Failure 404 {object} models.ErrorResponse "Asset not found"
// @Router /assets/{ip} [get]
func (h *AssetHandler) GetAssetByIP(c *gin.Context) {
	ip := c.Param("ip")

	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipRegex.MatchString(ip) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Message: "Invalid parameter"})
		return
	}

	for _, asset := range h.assetList {
		if asset.Address == ip {
			c.JSON(http.StatusOK, models.ConvertAsset(asset))
			return
		}
	}

	c.JSON(http.StatusNotFound, models.ErrorResponse{Message: "Asset not found"})
}
