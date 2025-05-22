package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ansiRegex is used to remove ANSI color codes.
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[mKHF]`)

// lineNumRegex is used to remove the optional [Line: XXX] part at the end.
var lineNumRegex = regexp.MustCompile(`\s*\[Line: \d+\]\s*$`)

// processMantraLine processes a single line of mantra tool output.
// It extracts the secret and URL, formatting them as "secret - URL".
// Lines not starting with "[+] " (after ANSI codes are stripped) are ignored.
func processMantraLine(line string) string {
	// Step 1: Remove ANSI color codes.
	cleanLine := ansiRegex.ReplaceAllString(line, "")

	// Step 2: Check for the required prefix.
	if !strings.HasPrefix(cleanLine, "[+] ") {
		return "" // Ignore lines that don't start with "[+] ".
	}

	// Step 3: Remove the prefix and trim whitespace.
	contentLine := strings.TrimPrefix(cleanLine, "[+] ")
	contentLine = strings.TrimSpace(contentLine)

	// Step 3.5: Remove the optional [Line: XXX] part from the end.
	contentLine = lineNumRegex.ReplaceAllString(contentLine, "")
	contentLine = strings.TrimSpace(contentLine) // Trim again in case the regex left spaces

	// Step 4: Locate the secret and URL.
	// The secret is expected to be enclosed in the last pair of square brackets "[]".
	// The URL is expected to be the part before these brackets.

	lastBracketOpen := strings.LastIndex(contentLine, "[")
	lastBracketClose := strings.LastIndex(contentLine, "]")

	// Validate the positions of the brackets.
	if lastBracketOpen == -1 || lastBracketClose == -1 || lastBracketOpen >= lastBracketClose || lastBracketClose != len(contentLine)-1 {
		// If brackets are not found, or not at the very end, the line is malformed for our parsing.
		// Try to split by "  [" as a fallback for structures like "URL  [secret]"
		parts := strings.SplitN(contentLine, "  [", 2)
		if len(parts) == 2 {
			urlPart := strings.TrimSpace(parts[0])
			secretPartWithBracket := parts[1]
			if strings.HasSuffix(secretPartWithBracket, "]") {
				secretValue := strings.TrimSuffix(secretPartWithBracket, "]")
				secretValue = strings.TrimSpace(secretValue)
				if urlPart != "" && secretValue != "" {
					return fmt.Sprintf("%s - %s", secretValue, urlPart)
				}
			}
		}
		return "" // If alternative parsing also fails.
	}

	// Original logic if brackets are found correctly at the end.
	urlPart := strings.TrimSpace(contentLine[:lastBracketOpen])
	secretValue := strings.TrimSpace(contentLine[lastBracketOpen+1 : lastBracketClose])

	if urlPart == "" || secretValue == "" {
		return "" // If either part is empty, consider it not a valid find.
	}

	return fmt.Sprintf("%s - %s", secretValue, urlPart)
}
