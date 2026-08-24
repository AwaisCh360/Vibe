package api

import (
	"net/http"

	"armur-codescanner/internal/db"
	"armur-codescanner/internal/models"

	"github.com/gin-gonic/gin"
)

type UpdateProfileRequest struct {
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	CompanyName string `json:"company_name" binding:"required"`
}

type UpdatePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// @Summary Update User Profile
// @Description Updates the user's first name, last name, and company name
// @Tags User Profile
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body UpdateProfileRequest true "Profile Data"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/user/profile [put]
func UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	idFloat, _ := userID.(float64)

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database := db.GetDB()
	var user models.User
	if err := database.First(&user, uint(idFloat)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.CompanyName = req.CompanyName

	if err := database.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// @Summary Update User Password
// @Description securely updates the user's password
// @Tags User Profile
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body UpdatePasswordRequest true "Password Data"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/user/password [put]
func UpdatePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	idFloat, _ := userID.(float64)

	var req UpdatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database := db.GetDB()
	var user models.User
	if err := database.First(&user, uint(idFloat)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify old password
	if err := user.CheckPassword(req.OldPassword); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect old password"})
		return
	}

	// Hash new password
	if err := user.SetPassword(req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	if err := database.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}
