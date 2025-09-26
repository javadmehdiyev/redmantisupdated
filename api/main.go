// Package main provides a REST API for network asset discovery and management
// @title RedMantis Network Discovery API
// @version 1.0
// @description A comprehensive API for network asset discovery, port scanning, and credential testing
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http https

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	_ "redmantis_api/docs" // Generated Swagger docs

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Asset represents a network asset with its properties and discovered services
type Asset struct {
	Address         string     `json:"address" example:"10.1.1.13" description:"IP address of the asset"`
	Hostname        string     `json:"hostname" example:"cavads-MacBook-Pro.local." description:"Hostname of the asset"`
	Os              string     `json:"os" example:"unknown" description:"Operating system of the asset"`
	Type            string     `json:"type" example:"unknown" description:"Type of the asset"`
	Hardware        string     `json:"hardware" example:"unknown" description:"Hardware information of the asset"`
	MacVendor       string     `json:"mac_vendor" example:"unknown" description:"MAC address vendor"`
	Mac             string     `json:"mac" example:"e2:0f:5c:18:7f:af" description:"MAC address of the asset"`
	Screenshot      string     `json:"screenshot" example:"" description:"Screenshot URL or path"`
	Date            time.Time  `json:"date" example:"2025-09-26T11:24:47.994799+04:00" description:"Discovery date"`
	Ports           []Port     `json:"ports" description:"List of open ports and services"`
	CredentialTests []CredTest `json:"credential_tests" description:"List of credential tests performed"`
}

// Port represents an open port with its service information
type Port struct {
	Number    int    `json:"number" example:"3306" description:"Port number"`
	Service   string `json:"service" example:"MySQL 8.0.43" description:"Service running on the port"`
	Banner    string `json:"banner" example:"MySQL 8.0.43" description:"Service banner information"`
	State     string `json:"state" example:"open" description:"Port state (open/closed/filtered)"`
	Transport string `json:"transport" example:"tcp" description:"Transport protocol (tcp/udp)"`
}

// CredTest represents a credential test result
type CredTest struct {
	Service  string `json:"service" example:"postgresql" description:"Service that was tested"`
	Username string `json:"username" example:"postgres" description:"Username used in the test"`
	Password string `json:"password" example:"postgres" description:"Password used in the test"`
	Success  bool   `json:"success" example:"true" description:"Whether the credential test was successful"`
}

// AssetList represents a paginated list of assets
type AssetList struct {
	TotalAssets int     `json:"total_assets" example:"21" description:"Total number of assets"`
	CurrentPage int     `json:"current_page" example:"1" description:"Current page number"`
	PageSize    int     `json:"page_size" example:"10" description:"Number of assets per page"`
	TotalPages  int     `json:"total_pages" example:"3" description:"Total number of pages"`
	Data        []Asset `json:"data" description:"List of assets for the current page"`
}

// Error represents an error response
type Error struct {
	Message string `json:"message" example:"Asset not found" description:"Error message"`
}

// Global variable to store assets - will be loaded from results.json
var assets []Asset

// loadAssetsFromJSON loads assets data from the results.json file
func loadAssetsFromJSON() error {
	// Read the JSON file
	data, err := os.ReadFile("../results.json")
	if err != nil {
		return err
	}

	// Unmarshal JSON data into assets slice
	err = json.Unmarshal(data, &assets)
	if err != nil {
		return err
	}

	// Set default screenshot value for assets that don't have it
	for i := range assets {
		if assets[i].Screenshot == "" {
			assets[i].Screenshot = ""
		}
		// Initialize empty slices if they are nil
		if assets[i].Ports == nil {
			assets[i].Ports = []Port{}
		}
		if assets[i].CredentialTests == nil {
			assets[i].CredentialTests = []CredTest{}
		}
	}

	log.Printf("Successfully loaded %d assets from results.json", len(assets))
	return nil
}

// getAssets handles the GET /assets endpoint
// @Summary Get paginated list of assets
// @Description Retrieve a paginated list of all discovered network assets with optional filtering
// @Tags assets
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)" default(1)
// @Param size query int false "Number of assets per page (default: 10)" default(10)
// @Success 200 {object} AssetList "Successfully retrieved assets"
// @Failure 400 {object} Error "Invalid parameters"
// @Router /assets [get]
func getAssets(c *gin.Context) {
	sizeParam := c.Query("size")
	pageParam := c.Query("page")

	var size int = 10 // default page size
	var page int = 1  // default page number
	var err error

	// Parse size parameter
	if sizeParam != "" {
		size, err = strconv.Atoi(sizeParam)
		if err != nil || size < 1 {
			c.JSON(http.StatusBadRequest, Error{Message: "Invalid size parameter"})
			return
		}
	}

	if pageParam != "" {
		page, err = strconv.Atoi(pageParam)
		if err != nil || page < 1 {
			c.JSON(http.StatusBadRequest, Error{Message: "Invalid page parameter"})
			return
		}
	}

	totalAssets := len(assets)
	totalPages := (totalAssets + size - 1) / size

	// Offseti Hesablamaq
	offset := (page - 1) * size

	// Sehifeni Check ele
	if offset >= totalAssets && totalAssets > 0 {
		c.JSON(http.StatusBadRequest, Error{Message: "Page out of bounds"})
		return
	}

	// Calculate end index
	end := offset + size
	if end > totalAssets {
		end = totalAssets
	}

	// Get paginated data
	var paginatedData []Asset
	if offset < totalAssets {
		paginatedData = assets[offset:end]
	} else {
		paginatedData = []Asset{}
	}

	response := AssetList{
		TotalAssets: totalAssets,
		CurrentPage: page,
		PageSize:    size,
		TotalPages:  totalPages,
		Data:        paginatedData,
	}

	c.JSON(http.StatusOK, response)
}

// getAssetByIP handles the GET /assets/:ip endpoint
// @Summary Get asset by IP address
// @Description Retrieve detailed information about a specific network asset by its IP address
// @Tags assets
// @Accept json
// @Produce json
// @Param ip path string true "IP address of the asset" example(10.1.1.13)
// @Success 200 {object} Asset "Successfully retrieved asset"
// @Failure 400 {object} Error "Invalid IP address format"
// @Failure 404 {object} Error "Asset not found"
// @Router /assets/{ip} [get]
func getAssetByIP(c *gin.Context) {
	ip := c.Param("ip")

	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipRegex.MatchString(ip) {
		c.JSON(http.StatusBadRequest, Error{Message: "Invalid parameter"})
		return
	}

	for _, asset := range assets {
		if asset.Address == ip {
			c.JSON(http.StatusOK, asset)
			return
		}
	}

	c.JSON(http.StatusNotFound, Error{Message: "Asset not found"})
}

func main() {
	// Load assets from results.json file
	if err := loadAssetsFromJSON(); err != nil {
		log.Fatal("Failed to load assets from results.json:", err)
	}

	r := gin.Default()

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.GET("/assets", getAssets)

	r.GET("/assets/:ip", getAssetByIP)

	r.Run(":8080")
}
