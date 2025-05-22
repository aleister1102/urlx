package main

import (
	"strings"
)

func processDirsearchLine(line string) string {
	if strings.HasPrefix(line, "#") {
		return ""
	}

	fields := strings.Fields(line)
	// Expected format: STATUS SIZE URL ... [-> REDIRECTS TO: REDIRECT_URL]
	// We need at least 3 fields for STATUS, SIZE, URL
	if len(fields) < 3 {
		return ""
	}

	// The URL is usually the 3rd field (index 2)
	originalURL := fields[2]
	if !isValidURL(originalURL) {
		// If the third field isn't a URL, this line isn't what we expect.
		// The bash script tries to read status, size, initial_url_part.
		// Let's try to be a bit more robust by finding the first valid URL.
		foundURL := ""
		for _, field := range fields {
			if isValidURL(field) {
				foundURL = field
				break
			}
		}
		if foundURL == "" {
			return ""
		}
		originalURL = foundURL
	}

	var redirectURL string
	redirectMarker := "-> REDIRECTS TO:"
	lineStr := strings.Join(fields, " ") // Rejoin for easier searching of the marker phrase

	if idx := strings.Index(lineStr, redirectMarker); idx != -1 {
		potentialRedirect := strings.TrimSpace(lineStr[idx+len(redirectMarker):])
		// The redirect URL might be followed by other information, so take the first space-separated token.
		redirectParts := strings.Fields(potentialRedirect)
		if len(redirectParts) > 0 && isValidURL(redirectParts[0]) {
			redirectURL = redirectParts[0]
		}
	}

	urlToProcess := originalURL
	if extractRedirect && redirectURL != "" {
		urlToProcess = redirectURL
	}

	if urlToProcess == "" { // Should not happen if originalURL was valid
		return ""
	}

	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		return finalURL
	}
	return ""
}
