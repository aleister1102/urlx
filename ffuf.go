package main

import (
	"net/url"
	"strings"
)

// processFfufLine parses a single line of ffuf's CSV output.
// It applies match and filter logic for status code, content type, and content length.
func processFfufLine(line string,
	filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchTypesRaw string, matchLengthsRaw string) string {

	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "FUZZ,url,redirectlocation") {
		return ""
	}

	parts := strings.Split(trimmedLine, ",")
	if len(parts) < 10 {
		return ""
	}

	rawURL := parts[1]
	redirectLocation := parts[2]
	statusCodeStr := parts[4]
	contentLengthStr := parts[5]
	contentType := parts[8]

	// --- Match Filters (Inclusive, AND logic) ---
	if matchCodesRaw != "" && !isMatch(statusCodeStr, matchCodesRaw) {
		return ""
	}
	if matchLengthsRaw != "" && !isMatch(contentLengthStr, matchLengthsRaw) {
		return ""
	}
	if matchTypesRaw != "" && !isContentTypeMatch(contentType, matchTypesRaw) {
		return ""
	}

	// --- Filter-Out Filters (Exclusive) ---
	if filterCodesRaw != "" && isMatch(statusCodeStr, filterCodesRaw) {
		return ""
	}
	if filterLengthsRaw != "" && isMatch(contentLengthStr, filterLengthsRaw) {
		return ""
	}
	if filterTypesRaw != "" && isContentTypeMatch(contentType, filterTypesRaw) {
		return ""
	}

	outputURL := rawURL
	if extractRedirect && redirectLocation != "" {
		redirectURL, err := url.Parse(redirectLocation)
		if err == nil {
			if redirectURL.IsAbs() {
				outputURL = redirectLocation
			} else {
				originalURL, errOrig := url.Parse(rawURL)
				if errOrig == nil {
					outputURL = originalURL.ResolveReference(redirectURL).String()
				} else {
					outputURL = redirectLocation
				}
			}
		} else {
			if !strings.HasPrefix(redirectLocation, "http://") && !strings.HasPrefix(redirectLocation, "https://") {
				base, errBase := url.Parse(rawURL)
				if errBase == nil {
					resolved := base.ResolveReference(&url.URL{Path: redirectLocation})
					outputURL = resolved.String()
				}
			}
		}
	}

	if stripComponents {
		outputURL = stripURLComponents(outputURL)
	}

	if !isValidURL(outputURL) {
		if isValidURL(rawURL) {
			if stripComponents {
				return stripURLComponents(rawURL)
			}
			return rawURL
		}
		return ""
	}

	return outputURL
}
