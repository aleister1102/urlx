package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// wafKindFilter is a global variable set by the -k flag in main.go

func processWafw00fLine(line string) []string {
	// 1. Extract the first URL
	// Regex to capture the first http/https URL on the line
	urlExtractRegex := regexp.MustCompile(`^\s*(https?://[^\s]+)`)
	urlMatch := urlExtractRegex.FindStringSubmatch(line)

	if urlMatch == nil || len(urlMatch) < 2 {
		return nil // No URL found
	}
	fullMatchedURL := urlMatch[1]

	// 2. Parse and clean the URL (remove query and fragment)
	parsedURL, err := url.Parse(fullMatchedURL)
	if err != nil {
		return nil // Invalid URL
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	displayURL := parsedURL.String()

	// 3. Extract the WAF name (text after the last closing parenthesis)
	lastParenIndex := strings.LastIndex(line, ")")
	if lastParenIndex == -1 {
		return nil // Line format does not match expected structure
	}
	extractedWafName := strings.TrimSpace(line[lastParenIndex+1:])

	if extractedWafName == "" {
		return nil // No WAF name found after parenthesis
	}

	// 4. Determine the actual kind of the WAF
	actualKind := ""
	switch extractedWafName {
	case "None":
		actualKind = "none"
	case "Generic":
		actualKind = "generic"
	default:
		actualKind = "known"
	}

	// 5. Filter based on wafKindFilter (set by -k flag from main.go)
	if wafKindFilter == actualKind {
		if actualKind == "none" {
			return []string{displayURL} // Only URL for 'none' kind
		} else {
			return []string{fmt.Sprintf("%s - %s", displayURL, extractedWafName)} // URL - WAFName for 'generic' and 'known'
		}
	}

	return nil // Did not match the filter
}
