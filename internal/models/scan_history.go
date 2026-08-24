package models

import (
	"gorm.io/gorm"
)

// ScanHistory represents a scan initiated by a user in the SaaS platform.
// This is used to build dashboard analytics and history views.
type ScanHistory struct {
	gorm.Model
	UserID        uint   `gorm:"index;not null" json:"user_id"`
	User          User   `gorm:"foreignKey:UserID" json:"-"`
	TaskID        string `gorm:"uniqueIndex;not null" json:"task_id"`
	RepositoryURL string `gorm:"not null" json:"repository_url"`
	Status        string `gorm:"default:'pending'" json:"status"` // pending, running, success, failed
	CriticalBugs  int    `gorm:"default:0" json:"critical_bugs"`
	HighBugs      int    `gorm:"default:0" json:"high_bugs"`
	MediumBugs    int    `gorm:"default:0" json:"medium_bugs"`
	LowBugs       int    `gorm:"default:0" json:"low_bugs"`
}
