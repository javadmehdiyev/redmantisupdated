package handlers

import (
	"log"
	"net/http"
	"strconv"

	"redmantis/api/models"
	"redmantis/internal/assets"

	"github.com/gin-gonic/gin"
)

type NucleiAssetHandler struct {
	assetList []assets.NucleiAsset
}

func NewNucleiAssetHandler() *NucleiAssetHandler {
	handler := &NucleiAssetHandler{}
	if err := handler.loadAssets(); err != nil {
		log.Fatal("Failed to load nuclei assets from results.json:", err)
	}
	return handler
}

func (h *NucleiAssetHandler) loadAssets() error {
	assetList, err := assets.LoadNucleiFromJSON("../nuclei_assets.json")
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

// GetNucleiAssets handles the GET /nuclei-assets endpoint
// @Summary Get paginated list of nuclei assets
// @Description Retrieve a paginated list of assets enriched with nuclei scan data
// @Tags nuclei
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)" default(1)
// @Param size query int false "Number of assets per page (default: 10)" default(10)
// @Success 200 {object} models.NucleiAssetListResponse "Successfully retrieved nuclei assets"
// @Failure 400 {object} models.ErrorResponse "Invalid parameters"
// @Router /nuclei-assets [get]
func (h *NucleiAssetHandler) GetNucleiAssets(c *gin.Context) {
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
	var paginatedData []assets.NucleiAsset
	if offset < totalAssets {
		paginatedData = h.assetList[offset:end]
	} else {
		paginatedData = []assets.NucleiAsset{}
	}

	response := models.NucleiAssetListResponse{
		TotalAssets: totalAssets,
		CurrentPage: page,
		PageSize:    size,
		TotalPages:  totalPages,
		Data:        models.ConvertNucleiAssets(paginatedData),
	}

	c.JSON(http.StatusOK, response)
}
