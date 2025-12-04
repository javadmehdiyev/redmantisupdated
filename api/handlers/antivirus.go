package handlers

import (
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"os"
)

type AntivirusHandler struct {
}

func NewAntivirusHandler() *AntivirusHandler {
	handler := &AntivirusHandler{}
	return handler
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
