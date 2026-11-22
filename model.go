package main

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

type ThreatFields struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type CreateRequest struct {
	MD5 string `json:"md5"`
	ThreatFields
}

type Threat struct {
	MD5 string `json:"md5"`
	ThreatFields
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (f *ThreatFields) normalizeAndValidate() error {
	f.Name = strings.TrimSpace(f.Name)
	f.Description = strings.TrimSpace(f.Description)
	nameLength := utf8.RuneCountInString(f.Name)
	if nameLength == 0 || nameLength > 200 {
		return errors.New("name must contain 1 to 200 characters")
	}
	if utf8.RuneCountInString(f.Description) > 2000 {
		return errors.New("description must contain at most 2000 characters")
	}
	if f.Severity == "" {
		f.Severity = "unknown"
	}
	switch f.Severity {
	case "unknown", "low", "medium", "high", "critical":
		return nil
	default:
		return errors.New("severity must be unknown, low, medium, high or critical")
	}
}
