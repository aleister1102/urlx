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

func processHttpxLine(line string,
	filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchTypesRaw string, matchLengthsRaw string, preserveContent bool) (string, []string) {

	anyFilterActive := filterCodesRaw != "" || filterTypesRaw != "" || filterLengthsRaw != "" ||
		matchCodesRaw != "" || matchTypesRaw != "" || matchLengthsRaw != ""

	// If -pc is on and no filters are active, just pass through the line.
	if preserveContent && !anyFilterActive {
		return line, nil
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return "", nil
	}

	var highlights []string

	// Only perform expensive parsing if any filter/matcher is active.
	if anyFilterActive {

		var statusCodeStr, statusCodeWithBrackets, contentLengthStr, contentType string

		// Regex to find the first bracketed part that contains status codes like [200] or [301,200]
		reStatus := regexp.MustCompile(`\[(\d{3}(?:,\s*\d{3})*)\]`)
		statusMatches := reStatus.FindStringSubmatch(line)
		if len(statusMatches) > 1 {
			statusCodeWithBrackets = statusMatches[0] // e.g., "[301,200]"
			statusCodeStr = statusMatches[1]          // e.g., "301,200"
		}

		// Use the more general regex to find other fields like content length and type
		reGeneral := regexp.MustCompile(`\[(.*?)\]`)
		matches := reGeneral.FindAllStringSubmatch(line, -1)

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
				return "", nil
			}
			highlights = append(highlights, statusCodeWithBrackets)
		}
		if matchLengthsRaw != "" {
			if contentLengthStr == "" || !isMatch(contentLengthStr, matchLengthsRaw) {
				return "", nil
			}
			highlights = append(highlights, contentLengthStr)
		}
		if matchTypesRaw != "" {
			if contentType == "" || !isContentTypeMatch(contentType, matchTypesRaw) {
				return "", nil
			}
			highlights = append(highlights, contentType)
		}

		// --- Filter-Out Filters (Exclusive) ---
		if filterCodesRaw != "" && statusCodeStr != "" && checkStatusCodeLogic(statusCodeStr, filterCodesRaw, false) {
			return "", nil
		}
		if filterLengthsRaw != "" && contentLengthStr != "" && isMatch(contentLengthStr, filterLengthsRaw) {
			return "", nil
		}
		if filterTypesRaw != "" && contentType != "" && isContentTypeMatch(contentType, filterTypesRaw) {
			return "", nil
		}
	}

	// If -pc is used, it means the line has passed any active filters. Return it with highlights.
	if preserveContent {
		return line, highlights
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
		return finalURL, nil
	}
	return "", nil
}
