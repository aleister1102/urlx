package main

import (
	"strings"
)

// processNucleiLine processes a single line of nuclei output.
// Format: [template-id] [protocol] [severity] URL
//
//	or: [template-id] [protocol] [severity] URL ["version"]
//
// Extracts the URL from each line.
func processNucleiLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Skip lines that don't start with '[' (like separator lines or headers)
	if !strings.HasPrefix(line, "[") {
		return ""
	}

	// Split the line into fields
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return "" // Not enough parts for the expected format
	}

	// Try to get URL from the 4th position (index 3) first
	// This handles the format: [template-id] [protocol] [severity] URL ["version"]
	if len(parts) >= 4 {
		urlCandidate := parts[3]
		if isValidURL(urlCandidate) {
			return urlCandidate
		}
	}

	// Fallback: try the last part for backward compatibility
	// This handles the format: [template-id] [protocol] [severity] URL
	urlCandidate := parts[len(parts)-1]
	if isValidURL(urlCandidate) {
		return urlCandidate
	}

	return ""
}
