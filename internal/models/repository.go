package models

import "gorm.io/gorm"

// Repository represents a git repository connected to the SaaS platform.
type Repository struct {
	gorm.Model
	UserID    uint   `gorm:"not null" json:"user_id"`
	URL       string `gorm:"not null" json:"url"`
	Branch    string `json:"branch"`
	IsPrivate bool   `json:"is_private"`
	Token     string `json:"-"` // Encrypted PAT for private repos, hidden from JSON
}
