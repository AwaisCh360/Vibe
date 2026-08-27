package models

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	
	"gorm.io/gorm"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security finding from any tool.
type Finding struct {
	gorm.Model
	ScanHistoryID uint   `gorm:"index" json:"scan_history_id"`
	RepositoryID  uint   `gorm:"index" json:"repository_id"`
	Fingerprint   string `gorm:"uniqueIndex" json:"fingerprint"`
	Tool          string `json:"tool"`
	Source      string   `json:"source,omitempty"` // sast | dast | sca | secrets | iac | exploit | attack_path
	Category    string   `json:"category"`         // security_issues | antipatterns_bugs | complex_functions | etc.
	File        string   `json:"file"`
	Line        int      `json:"line"`
	EndLine     int      `json:"end_line,omitempty"`
	Column      int      `json:"column,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"` // high | medium | low
	Message     string   `json:"message"`
	Snippet     string   `json:"snippet,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Status      string   `json:"status" gorm:"default:'open'"` // open, resolved, ignored, false_positive
}

// ComputeFingerprint generates a SHA256 fingerprint for the finding.
func (f *Finding) ComputeFingerprint() {
	data := f.Tool + "|" + f.File + "|" + strconv.Itoa(f.Line) + "|" + f.RuleID + "|"
	if len(f.Message) > 64 {
		data += f.Message[:64]
	} else {
		data += f.Message
	}
	hash := sha256.Sum256([]byte(data))
	f.Fingerprint = fmt.Sprintf("%x", hash[:16]) // 32-char hex string
}

// ScanResult represents the complete output of a scan.
type ScanResult struct {
	TaskID    string      `json:"task_id"`
	Status    string      `json:"status"` // success | failed | cancelled
	Findings  []Finding   `json:"findings"`
	Errors    []ScanError `json:"errors,omitempty"`
	Meta      ScanMeta    `json:"meta"`
	DedupMeta *DedupMeta  `json:"dedup,omitempty"`
}

// ScanError captures a tool-level failure that occurred during a scan.
type ScanError struct {
	Tool    string `json:"tool"`
	Message string `json:"message"`
}

// ScanMeta holds metadata about the scan execution.
type ScanMeta struct {
	Language  string   `json:"language"`
	Mode      string   `json:"mode"` // simple | advanced
	ToolsRun  []string `json:"tools_run"`
	Duration  float64  `json:"duration_secs"`
	FileCount int      `json:"file_count,omitempty"`
}

// DedupMeta holds deduplication statistics.
type DedupMeta struct {
	RawCount     int `json:"raw_count"`
	AfterDedup   int `json:"after_dedup"`
	DupesRemoved int `json:"dupes_removed"`
}

// SeverityOrder returns a numeric value for severity comparison.
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
