package main

import (
	"regexp"
	"strconv"
	"strings"
)

func processDirsearchLine(line string, filterCodesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchLengthsRaw string, preserveContent bool) string {

	// Skip comment lines
	if strings.HasPrefix(line, "#") {
		return ""
	}

	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return ""
	}

	anyFilterActive := filterCodesRaw != "" || filterLengthsRaw != "" ||
		matchCodesRaw != "" || matchLengthsRaw != ""

	// If -pc is on and no filters are active, just pass through the original line
	if preserveContent && !anyFilterActive {
		return line
	}

	fields := strings.Fields(cleanLine)
	// Expected format: STATUS SIZE URL [-> REDIRECT_URL]
	// We need at least 3 fields for STATUS, SIZE, URL
	if len(fields) < 3 {
		return ""
	}

	// Parse status code (first field)
	statusCodeStr := fields[0]
	if _, err := strconv.Atoi(statusCodeStr); err != nil {
		// First field is not a number, skip this line
		return ""
	}

	// Parse size (second field) - can be in formats like "125KB", "0B", "185B"
	sizeStr := fields[1]
	contentLengthStr := ""
	// Try to extract numeric part from size (e.g., "125KB" -> "125", "0B" -> "0")
	reSize := regexp.MustCompile(`^(\d+)[A-Za-z]*$`)
	if sizeMatch := reSize.FindStringSubmatch(sizeStr); len(sizeMatch) > 1 {
		contentLengthStr = sizeMatch[1]
	}

	// The URL is the 3rd field (index 2)
	originalURL := fields[2]
	if !isValidURL(originalURL) {
		return ""
	}

	// Look for redirect URL after "->"
	var redirectURL string
	for i := 3; i < len(fields); i++ {
		if fields[i] == "->" && i+1 < len(fields) {
			potentialRedirect := fields[i+1]
			// Handle relative redirects by prepending the original URL's scheme and host
			if strings.HasPrefix(potentialRedirect, "/") {
				// Parse original URL to get scheme and host
				if parsedOriginal := parseURL(originalURL); parsedOriginal != nil {
					potentialRedirect = parsedOriginal.Scheme + "://" + parsedOriginal.Host + potentialRedirect
				}
			}
			if isValidURL(potentialRedirect) {
				redirectURL = potentialRedirect
			} else if strings.HasPrefix(potentialRedirect, "/") {
				// Store relative redirect as-is
				redirectURL = potentialRedirect
			}
			break
		}
	}

	// Apply filters if any are active
	if anyFilterActive {
		// --- Match Filters (Inclusive, AND logic) ---
		if matchCodesRaw != "" {
			if statusCodeStr == "" || !isMatch(statusCodeStr, matchCodesRaw) {
				return ""
			}
		}
		if matchLengthsRaw != "" {
			if contentLengthStr == "" || !isMatch(contentLengthStr, matchLengthsRaw) {
				return ""
			}
		}

		// --- Filter-Out Filters (Exclusive) ---
		if filterCodesRaw != "" && statusCodeStr != "" && isMatch(statusCodeStr, filterCodesRaw) {
			return ""
		}
		if filterLengthsRaw != "" && contentLengthStr != "" && isMatch(contentLengthStr, filterLengthsRaw) {
			return ""
		}
	}

	// If -pc is used and filters passed, return original line
	if preserveContent {
		return line
	}

	// Determine which URL to process
	urlToProcess := originalURL
	if extractRedirect && redirectURL != "" {
		urlToProcess = redirectURL
	}

	// Apply strip components if requested
	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		return finalURL
	}
	return ""
}

// Helper function to parse a URL
func parseURL(rawURL string) *struct {
	Scheme string
	Host   string
} {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil
	}

	// Simple parsing to extract scheme and host
	var scheme, host string
	if strings.HasPrefix(rawURL, "https://") {
		scheme = "https"
		rest := strings.TrimPrefix(rawURL, "https://")
		if idx := strings.Index(rest, "/"); idx != -1 {
			host = rest[:idx]
		} else {
			host = rest
		}
	} else if strings.HasPrefix(rawURL, "http://") {
		scheme = "http"
		rest := strings.TrimPrefix(rawURL, "http://")
		if idx := strings.Index(rest, "/"); idx != -1 {
			host = rest[:idx]
		} else {
			host = rest
		}
	}

	if host == "" {
		return nil
	}

	return &struct {
		Scheme string
		Host   string
	}{Scheme: scheme, Host: host}
}
