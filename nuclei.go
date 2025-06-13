package main

import (
	"strings"
)

// processNucleiLine processes a single line of nuclei output.
// Format: [template-id] [protocol] [severity] URL
// Extracts the URL from the end of each line.
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

	// The URL should be the last part
	urlCandidate := parts[len(parts)-1]

	// Validate if it's a proper URL
	if isValidURL(urlCandidate) {
		return urlCandidate
	}

	return ""
}
