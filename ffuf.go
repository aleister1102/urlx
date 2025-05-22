package main

import (
	"strings"
)

func processFfufLine(line string) string {
	// Skip header lines starting with "FUZZ,"
	if strings.HasPrefix(line, "FUZZ,") {
		return ""
	}

	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return ""
	}

	var originalURL, redirectCandidate string

	valAtIdx1 := parts[1]
	var valAtIdx2, valAtIdx3 string
	if len(parts) > 2 {
		valAtIdx2 = parts[2]
	}
	if len(parts) > 3 {
		valAtIdx3 = parts[3]
	}

	if isValidURL(valAtIdx1) {
		// Format: FUZZ_KEYWORD,URL,REDIRECT_URL?,...
		originalURL = valAtIdx1
		if valAtIdx2 != "" && isValidURL(valAtIdx2) {
			redirectCandidate = valAtIdx2
		}
	} else if valAtIdx2 != "" && isValidURL(valAtIdx2) {
		// Format: FUZZ_KEYWORD,METHOD,URL,REDIRECT_URL?,...
		originalURL = valAtIdx2
		if valAtIdx3 != "" && isValidURL(valAtIdx3) {
			redirectCandidate = valAtIdx3
		}
	} else {
		return "" // Not a recognizable ffuf data line
	}

	if originalURL == "" {
		return ""
	}

	urlToProcess := originalURL
	if extractRedirect && redirectCandidate != "" {
		urlToProcess = redirectCandidate
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