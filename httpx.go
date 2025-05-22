package main

import (
	"regexp"
	"strings"
)

func processHttpxLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return ""
	}

	urlToProcess := originalURL

	if extractRedirect {
		re := regexp.MustCompile(`\[(https?://[^]]*)\]`)
		matches := re.FindAllStringSubmatch(line, -1)
		if len(matches) > 0 {
			// Get the last match
			lastMatch := matches[len(matches)-1]
			if len(lastMatch) > 1 {
				actualRedirectURL := lastMatch[1]
				if isValidURL(actualRedirectURL) {
					urlToProcess = actualRedirectURL
				}
			}
		}
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