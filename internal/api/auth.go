package api

import (
	"net/http"

	"armur-codescanner/internal/db"
	"armur-codescanner/internal/middleware"
	"armur-codescanner/internal/models"

	"github.com/gin-gonic/gin"
)

type SignupRequest struct {
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	CompanyName string `json:"company_name" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// @Summary User Signup
// @Description Register a new user in the SaaS platform
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body SignupRequest true "Signup Data"
// @Success 201 {object} map[string]interface{}
// @Router /api/v1/auth/signup [post]
func Signup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database := db.GetDB()

	var existingUser models.User
	if err := database.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
		return
	}

	user := models.User{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		CompanyName: req.CompanyName,
		Email:       req.Email,
	}
	if err := user.SetPassword(req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	if err := database.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	token, err := middleware.GenerateJWT(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"token":   token,
		"user": map[string]interface{}{
			"id":           user.ID,
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"company_name": user.CompanyName,
			"email":        user.Email,
		},
	})
}

// @Summary User Login
// @Description Authenticate a user and return a JWT token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login Data"
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/auth/login [post]
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database := db.GetDB()

	var user models.User
	if err := database.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	token, err := middleware.GenerateJWT(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": map[string]interface{}{
			"id":           user.ID,
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"company_name": user.CompanyName,
			"email":        user.Email,
		},
	})
}

// @Summary Get Current User Info
// @Description Returns the profile information of the currently authenticated user
// @Tags Authentication
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/user/about [get]
func UserAbout(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	database := db.GetDB()
	var user models.User

	// Handle float64 conversion from JWT claims
	idFloat, ok := userID.(float64)
	if !ok {
		// Maybe it's uint from elsewhere
		if idUint, ok := userID.(uint); ok {
			idFloat = float64(idUint)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type in token"})
			return
		}
	}

	if err := database.Select("id", "created_at", "email", "first_name", "last_name", "company_name").First(&user, uint(idFloat)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           user.ID,
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
		"company_name": user.CompanyName,
		"email":        user.Email,
		"created_at":   user.CreatedAt,
	})
}
