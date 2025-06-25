package main

import (
	"net/url"
	"strings"
)

// processFfufLine parses a single line of ffuf's CSV output.
// It applies match and filter logic for status code, content type, and content length.
func processFfufLine(line string,
	filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string,
	matchCodesRaw string, matchTypesRaw string, matchLengthsRaw string, preserveContent bool) (string, []string) {

	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "FUZZ,url,redirectlocation") {
		return "", nil
	}

	parts := strings.Split(trimmedLine, ",")
	if len(parts) < 10 {
		return "", nil
	}

	rawURL := parts[1]
	redirectLocation := parts[2]
	statusCodeStr := parts[4]
	contentLengthStr := parts[5]
	contentType := parts[8]

	var highlights []string

	// --- Match Filters (Inclusive, AND logic) ---
	if matchCodesRaw != "" {
		if !isMatch(statusCodeStr, matchCodesRaw) {
			return "", nil
		}
		highlights = append(highlights, statusCodeStr)
	}
	if matchLengthsRaw != "" {
		if !isMatch(contentLengthStr, matchLengthsRaw) {
			return "", nil
		}
		highlights = append(highlights, contentLengthStr)
	}
	if matchTypesRaw != "" {
		if !isContentTypeMatch(contentType, matchTypesRaw) {
			return "", nil
		}
		highlights = append(highlights, contentType)
	}

	// --- Filter-Out Filters (Exclusive) ---
	if filterCodesRaw != "" && isMatch(statusCodeStr, filterCodesRaw) {
		return "", nil
	}
	if filterLengthsRaw != "" && isMatch(contentLengthStr, filterLengthsRaw) {
		return "", nil
	}
	if filterTypesRaw != "" && isContentTypeMatch(contentType, filterTypesRaw) {
		return "", nil
	}

	// At this point, the line has passed all filters.
	// If -pc is active, return the original trimmed line with highlights.
	if preserveContent {
		return trimmedLine, highlights
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
				return stripURLComponents(rawURL), nil
			}
			return rawURL, nil
		}
		return "", nil
	}

	// For non -pc mode, no highlights are returned
	return outputURL, nil
}
