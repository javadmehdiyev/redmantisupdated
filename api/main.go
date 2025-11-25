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
	_ "redmantis/api/docs" // Generated Swagger docs

	"redmantis/api/handlers"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	// Initialize handlers
	assetHandler := handlers.NewAssetHandler()
	nucleiAssetHandler := handlers.NewNucleiAssetHandler()

	// Setup Gin router
	r := gin.Default()

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Nuclei endpoints
	r.GET("/nuclei-assets", nucleiAssetHandler.GetNucleiAssets)

	// Asset endpoints
	r.GET("/assets", assetHandler.GetAssets)
	r.GET("/assets/:ip", assetHandler.GetAssetByIP)

	// Start server
	r.Run(":8080")
}
