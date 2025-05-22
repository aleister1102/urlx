package main

import (
	"net/url"
	"strings"
)

// processFfufLine parses a single line of ffuf's CSV output.
// It applies filters based on status code, content type, and content length.
// It extracts the URL (or redirect URL if extractRedirect is true).
// It strips URL components if stripComponents is true.
func processFfufLine(line string, filterCodesRaw string, filterTypesRaw string, filterLengthsRaw string) string {
	// ffuf CSV header (for reference, not strictly enforced by column index in this parser):
	// FUZZ,url,redirectlocation,position,status_code,content_length,content_words,content_lines,content_type,duration,resultfile

	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "FUZZ,url,redirectlocation") {
		return "" // Skip empty lines, comments, or the header
	}

	parts := strings.Split(trimmedLine, ",")
	if len(parts) < 10 { // Expecting at least 10 columns for a valid data line
		// fmt.Fprintf(os.Stderr, "Warning: Skipping malformed ffuf line (not enough columns): %s\n", trimmedLine)
		return ""
	}

	rawURL := parts[1]
	redirectLocation := parts[2]
	statusCodeStr := parts[4]
	contentLengthStr := parts[5]
	contentType := parts[8] // ffuf might output " " or "" for content_type

	// Apply filters
	if filterCodesRaw != "" {
		filterCodes := strings.Split(filterCodesRaw, ",")
		for _, code := range filterCodes {
			if strings.TrimSpace(code) == statusCodeStr {
				// fmt.Fprintf(os.Stderr, "Debug: Filtering out by status code '%s': %s\n", statusCodeStr, trimmedLine)
				return ""
			}
		}
	}

	if filterTypesRaw != "" {
		filterTypes := strings.Split(filterTypesRaw, ",")
		trimmedContentType := strings.TrimSpace(contentType)
		for _, ft := range filterTypes {
			// ffuf content types can sometimes have parameters like "text/html; charset=utf-8"
			// We should match if the provided filter type is a substring of the actual content type.
			// Or, if ffuf outputs an empty/space content type and the filter is for that.
			if strings.Contains(trimmedContentType, strings.TrimSpace(ft)) || (trimmedContentType == "" && strings.TrimSpace(ft) == "") {
				// fmt.Fprintf(os.Stderr, "Debug: Filtering out by content type '%s' (filter: '%s'): %s\n", trimmedContentType, ft, trimmedLine)
				return ""
			}
		}
	}

	if filterLengthsRaw != "" {
		filterLengths := strings.Split(filterLengthsRaw, ",")
		for _, length := range filterLengths {
			if strings.TrimSpace(length) == contentLengthStr {
				// fmt.Fprintf(os.Stderr, "Debug: Filtering out by content length '%s': %s\n", contentLengthStr, trimmedLine)
				return ""
			}
		}
	}

	outputURL := rawURL
	if extractRedirect && redirectLocation != "" {
		// Attempt to parse redirectLocation as a full URL.
		// If it's a relative path, try to resolve it against the original URL's scheme and host.
		redirectURL, err := url.Parse(redirectLocation)
		if err == nil {
			if redirectURL.IsAbs() {
				outputURL = redirectLocation
			} else {
				originalURL, errOrig := url.Parse(rawURL)
				if errOrig == nil {
					outputURL = originalURL.ResolveReference(redirectURL).String()
				} else {
					// Could not parse original URL, stick to redirectLocation as is, or maybe just rawURL
					// For now, if original parsing fails, we use the raw redirect string if it was chosen.
					// This case should be rare if rawURL itself was valid.
					outputURL = redirectLocation
				}
			}
		} else {
			// If redirectLocation is not a valid URL (e.g. malformed, or just a path for a misconfigured server)
			// we might fall back to rawURL or handle it as an error.
			// For now, if redirectLocation parsing fails, we'll just use it as a string if extractRedirect is on.
			// Or, more safely, stick to rawURL if redirect parsing fails. Let's stick to rawURL for safety.
			// A better approach for relative paths in redirectLocation:
			if !strings.HasPrefix(redirectLocation, "http://") && !strings.HasPrefix(redirectLocation, "https://") {
				base, errBase := url.Parse(rawURL)
				if errBase == nil {
					resolved := base.ResolveReference(&url.URL{Path: redirectLocation})
					outputURL = resolved.String()
				}
				// if base parsing fails, outputURL remains rawURL
			} else {
				// It looks like an absolute URL but failed to parse, could be an issue.
				// Default to rawURL if redirect is unusable.
			}
		}
	}

	if stripComponents {
		outputURL = stripURLComponents(outputURL)
	}

	if !isValidURL(outputURL) { // Final check to ensure we are outputting something that resembles a URL
		// This might happen if ffuf output is very strange or redirect logic leads to an invalid state.
		// Try to fall back to the original rawURL if that was valid and strip if necessary.
		if isValidURL(rawURL) {
			if stripComponents {
				return stripURLComponents(rawURL)
			}
			return rawURL
		}
		// fmt.Fprintf(os.Stderr, "Warning: Skipping ffuf line, final extracted URL is invalid: %s (from line: %s)\n", outputURL, trimmedLine)
		return ""
	}

	// Ensure status code is 2xx or 3xx before considering it a "successful" find, unless redirect is being extracted
	// For ffuf, usually all lines are "found" based on its own logic, but we might only care about certain ones.
	// However, the filtering flags are primary. If a user wants 403s, they can get them.
	// Let's remove this an rely on filtering flags.
	/*
		statusCode, err := strconv.Atoi(statusCodeStr)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "Warning: Skipping ffuf line, invalid status code: %s\n", statusCodeStr)
			return ""
		}
		if !( (statusCode >= 200 && statusCode < 300) || (extractRedirect && redirectLocation != "" && statusCode >=300 && statusCode < 400) ) {
			return ""
		}
	*/

	return outputURL
}
