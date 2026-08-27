package models

import (
	"gorm.io/gorm"
)

// ScanHistory represents a scan initiated by a user in the SaaS platform.
// This is used to build dashboard analytics and history views.
type ScanHistory struct {
	gorm.Model
	UserID        uint       `gorm:"index;not null" json:"user_id"`
	User          User       `gorm:"foreignKey:UserID" json:"-"`
	RepositoryID  *uint      `gorm:"index" json:"repository_id"`
	Repository    Repository `gorm:"foreignKey:RepositoryID" json:"-"`
	TaskID        string     `gorm:"uniqueIndex;not null" json:"task_id"`
	RepositoryURL string     `gorm:"not null" json:"repository_url"`
	ScanType      string     `json:"scan_type" gorm:"default:'quick'"`
	Categories    []string   `json:"categories" gorm:"serializer:json"`
	Options       string     `json:"options" gorm:"type:jsonb"`
	Status        string `gorm:"default:'pending'" json:"status"` // pending, running, success, failed
	CriticalBugs  int    `gorm:"default:0" json:"critical_bugs"`
	HighBugs      int    `gorm:"default:0" json:"high_bugs"`
	MediumBugs    int    `gorm:"default:0" json:"medium_bugs"`
	LowBugs       int    `gorm:"default:0" json:"low_bugs"`
}
