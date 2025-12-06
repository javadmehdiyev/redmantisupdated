package handlers

import (
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

type AntivirusHandler struct {
}

func NewAntivirusHandler() *AntivirusHandler {
	handler := &AntivirusHandler{}
	return handler
}

func (h *AntivirusHandler) CheckData(c *gin.Context) {
	fileName := c.Query("file")
	if fileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file parameter is required"})
		return
	}

	filePath := "./uploads/" + fileName

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{
			"exists":   false,
			"message":  "file not found",
			"filename": fileName,
		})
		return // <-- ОБЯЗАТЕЛЬНО!
	}

	// Если сюда дошло — файл существует
	c.JSON(http.StatusOK, gin.H{
		"exists":   true,
		"message":  "file exists",
		"filename": fileName,
	})
}

func (h *AntivirusHandler) LoadData(c *gin.Context) {
	fileName := c.PostForm("file_name")
	if fileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file_name is required"})
		return
	}

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	filePath := "./uploads/" + fileName

	if err := os.MkdirAll("./uploads", 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create directory"})
		return
	}

	out, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot save file"})
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot write file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "file uploaded",
		"filename": fileName,
	})
}
