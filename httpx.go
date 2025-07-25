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

// checkStatusCodeLogic handles the specific filtering/matching rules for httpx status codes.
// For matching (-mc), it performs a strict equality check.
// For filtering (-fc), it checks if any of the line's codes are in the user's filter list.
func checkStatusCodeLogic(lineCodesStr string, userList string, isForMatching bool) bool {
	userCodes := strings.Split(userList, ",")
	for i, code := range userCodes {
		userCodes[i] = strings.TrimSpace(code)
	}

	if isForMatching {
		// Strict match: the entire status code string from the tool (e.g., "301,200")
		// must exactly match one of the entries provided by the user.
		for _, userCodeSet := range userCodes {
			if lineCodesStr == userCodeSet {
				return true
			}
		}
		return false
	} else {
		// Filtering: checks if any single code from the line (e.g., "301" or "200")
		// exists in the user's filter list.
		lineCodes := strings.Split(lineCodesStr, ",")
		for _, lineCode := range lineCodes {
			trimmedLineCode := strings.TrimSpace(lineCode)
			for _, userCode := range userCodes {
				if trimmedLineCode == userCode {
					return true // Found a code to filter on
				}
			}
		}
		return false
	}
}

// stripAnsi removes ANSI escape codes from a string.
func stripAnsi(str string) string {
	// This regex handles common ANSI color codes, which was the source of the issue.
	const ansiRegex = "\x1b\\[[0-9;]*m"
	var re = regexp.MustCompile(ansiRegex)
	return re.ReplaceAllString(str, "")
}

func processHttpxLine(line string,
	filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchTypesRaw string, matchLengthsRaw string, preserveContent bool) string {

	// First, strip any ANSI color codes from the line to ensure clean parsing.
	cleanLine := stripAnsi(line)

	anyFilterActive := filterCodesRaw != "" || filterTypesRaw != "" || filterLengthsRaw != "" ||
		matchCodesRaw != "" || matchTypesRaw != "" || matchLengthsRaw != ""

	// If -pc is on and no filters are active, just pass through the original line.
	if preserveContent && !anyFilterActive {
		return line
	}

	parts := strings.Fields(cleanLine)
	if len(parts) == 0 {
		return ""
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return ""
	}

	if anyFilterActive {
		var statusCodeStr, contentLengthStr, contentType string

		// Regex to find the first bracketed part that contains status codes like [200] or [301,200]
		reStatus := regexp.MustCompile(`\[(\d{3}(?:,\s*\d{3})*)\]`)
		statusMatches := reStatus.FindStringSubmatch(cleanLine)
		if len(statusMatches) > 1 {
			statusCodeStr = statusMatches[1]
		}

		// Use the more general regex to find other fields like content length and type
		reGeneral := regexp.MustCompile(`\[(.*?)\]`)
		matches := reGeneral.FindAllStringSubmatch(cleanLine, -1)

		// Heuristics to find content length and type
		var clFound, ctFound bool
		for _, match := range matches {
			val := strings.TrimSpace(match[1])
			if !clFound {
				if _, err := strconv.Atoi(val); err == nil && val != statusCodeStr && !strings.Contains(statusCodeStr, val) {
					contentLengthStr = val
					clFound = true
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
		if matchCodesRaw != "" {
			if statusCodeStr == "" || !checkStatusCodeLogic(statusCodeStr, matchCodesRaw, true) {
				return ""
			}
		}
		if matchLengthsRaw != "" {
			if contentLengthStr == "" || !isMatch(contentLengthStr, matchLengthsRaw) {
				return ""
			}
		}
		if matchTypesRaw != "" {
			if contentType == "" || !isContentTypeMatch(contentType, matchTypesRaw) {
				return ""
			}
		}

		// --- Filter-Out Filters (Exclusive) ---
		if filterCodesRaw != "" && statusCodeStr != "" && checkStatusCodeLogic(statusCodeStr, filterCodesRaw, false) {
			return ""
		}
		if filterLengthsRaw != "" && contentLengthStr != "" && isMatch(contentLengthStr, filterLengthsRaw) {
			return ""
		}
		if filterTypesRaw != "" && contentType != "" && isContentTypeMatch(contentType, filterTypesRaw) {
			return ""
		}
	}

	// If -pc is used, it means the line has passed any active filters. Return it.
	if preserveContent {
		return line
	}

	urlToProcess := originalURL

	if extractRedirect {
		redirectRegex := regexp.MustCompile(`\[(https?://[^]]*)\]`)
		redirectMatches := redirectRegex.FindAllStringSubmatch(cleanLine, -1)
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
