package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Helper function to check if a value is in a comma-separated list.
func isMatch(value string, commaSeparatedList string) bool {
	items := strings.Split(commaSeparatedList, ",")
	trimmedValue := strings.TrimSpace(value)
	for _, item := range items {
		if strings.TrimSpace(item) == trimmedValue {
			return true
		}
	}
	return false
}

// Helper function for content type matching (substring check).
func isContentTypeMatch(value string, commaSeparatedList string) bool {
	items := strings.Split(commaSeparatedList, ",")
	trimmedValue := strings.TrimSpace(value)
	for _, item := range items {
		if strings.Contains(trimmedValue, strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func processHttpxLine(line string,
	filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchTypesRaw string, matchLengthsRaw string) string {

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return ""
	}

	// Only perform expensive parsing if any filter/matcher is active.
	if filterCodesRaw != "" || filterTypesRaw != "" || filterLengthsRaw != "" ||
		matchCodesRaw != "" || matchTypesRaw != "" || matchLengthsRaw != "" {

		re := regexp.MustCompile(`\[(.*?)\]`)
		matches := re.FindAllStringSubmatch(line, -1)
		var statusCodeStr, contentLengthStr, contentType string

		// Heuristic to find status code: the first 3-digit number.
		for _, match := range matches {
			val := strings.TrimSpace(match[1])
			if len(val) == 3 {
				if _, err := strconv.Atoi(val); err == nil {
					statusCodeStr = val
					break
				}
			}
		}

		// Heuristics to find content length (first number that isn't status code) and type (first with '/').
		var clFound, ctFound bool
		for _, match := range matches {
			val := strings.TrimSpace(match[1])
			if !clFound {
				if _, err := strconv.Atoi(val); err == nil {
					if val != statusCodeStr {
						contentLengthStr = val
						clFound = true
					}
				}
			}
			if !ctFound && strings.Contains(val, "/") {
				contentType = val
				ctFound = true
			}
			if clFound && ctFound {
				break
			}
		}

		// --- Match Filters (Inclusive, AND logic) ---
		if matchCodesRaw != "" && (statusCodeStr == "" || !isMatch(statusCodeStr, matchCodesRaw)) {
			return ""
		}
		if matchLengthsRaw != "" && (contentLengthStr == "" || !isMatch(contentLengthStr, matchLengthsRaw)) {
			return ""
		}
		if matchTypesRaw != "" && (contentType == "" || !isContentTypeMatch(contentType, matchTypesRaw)) {
			return ""
		}

		// --- Filter-Out Filters (Exclusive) ---
		if filterCodesRaw != "" && statusCodeStr != "" && isMatch(statusCodeStr, filterCodesRaw) {
			return ""
		}
		if filterLengthsRaw != "" && contentLengthStr != "" && isMatch(contentLengthStr, filterLengthsRaw) {
			return ""
		}
		if filterTypesRaw != "" && contentType != "" && isContentTypeMatch(contentType, filterTypesRaw) {
			return ""
		}
	}

	urlToProcess := originalURL

	if extractRedirect {
		redirectRegex := regexp.MustCompile(`\[(https?://[^]]*)\]`)
		redirectMatches := redirectRegex.FindAllStringSubmatch(line, -1)
		if len(redirectMatches) > 0 {
			lastMatch := redirectMatches[len(redirectMatches)-1]
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
