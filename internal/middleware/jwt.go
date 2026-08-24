package middleware

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var JWTSecret = []byte(getJWTSecret())

func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "super_secret_key_change_in_production"
	}
	return secret
}

// GenerateJWT creates a new JWT token for a user.
func GenerateJWT(userID uint, email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	return token.SignedString(JWTSecret)
}

// JWTMiddleware validates the JWT token or falls back to ARMUR_API_KEY for CI/CD.
func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Check for ARMUR_API_KEY (CI/CD Fallback)
		apiKey := c.GetHeader("X-API-Key")
		expectedKey := os.Getenv("ARMUR_API_KEY")
		if apiKey != "" && expectedKey != "" && apiKey == expectedKey {
			c.Set("client_type", "api_key")
			c.Next()
			return
		}

		// 2. Check for JWT Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Inject user info into context
		c.Set("user_id", claims["user_id"])
		c.Set("email", claims["email"])
		c.Set("client_type", "jwt")
		c.Next()
	}
}
