package db

import (
	"fmt"
	"os"
	"sync"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	dbInstance *gorm.DB
	dbOnce     sync.Once
	dbError    error
)

// InitDB initializes the PostgreSQL connection.
// It uses DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT env vars.
// Alternatively, it uses DB_DSN if provided.
func InitDB() (*gorm.DB, error) {
	dbOnce.Do(func() {
		dsn := os.Getenv("DB_DSN")
		if dsn == "" {
			host := os.Getenv("DB_HOST")
			if host == "" {
				host = "localhost"
			}
			port := os.Getenv("DB_PORT")
			if port == "" {
				port = "5432"
			}
			user := os.Getenv("DB_USER")
			if user == "" {
				user = "postgres"
			}
			password := os.Getenv("DB_PASSWORD")
			if password == "" {
				password = "password"
			}
			dbname := os.Getenv("DB_NAME")
			if dbname == "" {
				dbname = "armur"
			}

			dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
				host, user, password, dbname, port)
		}

		config := &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		}

		dbInstance, dbError = gorm.Open(postgres.Open(dsn), config)
	})

	return dbInstance, dbError
}

// GetDB returns the initialized database instance.
func GetDB() *gorm.DB {
	if dbInstance == nil {
		InitDB()
	}
	return dbInstance
}
