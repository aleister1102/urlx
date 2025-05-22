package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ansiRegex is used to remove ANSI color codes.
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[mKHF]`)

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

	// Step 4: Locate the secret and URL.
	// The primary expected format is "URL  [SECRET_VALUE]"
	// We use SplitN with "  [" as a delimiter between URL and the start of the secret part.
	parts := strings.SplitN(contentLine, "  [", 2)
	if len(parts) == 2 {
		urlPart := strings.TrimSpace(parts[0])
		secretPartWithBracket := parts[1]

		// The secret part should end with a closing bracket.
		if strings.HasSuffix(secretPartWithBracket, "]") {
			secretValue := strings.TrimSuffix(secretPartWithBracket, "]")
			secretValue = strings.TrimSpace(secretValue) // Trim spaces within the brackets as well

			if urlPart != "" && secretValue != "" {
				return fmt.Sprintf("%s - %s", secretValue, urlPart)
			}
		}
	}

	// Fallback: If the above SplitN doesn't match, try the LastIndex logic
	// This is for cases where the spacing might be different but structure "URL [SECRET]" (at the end) holds.
	lastBracketOpen := strings.LastIndex(contentLine, "[")
	lastBracketClose := strings.LastIndex(contentLine, "]")

	// Check if brackets are present and form the end of the string for the secret.
	if lastBracketOpen != -1 && lastBracketClose != -1 && lastBracketOpen < lastBracketClose && lastBracketClose == len(contentLine)-1 {
		urlPart := strings.TrimSpace(contentLine[:lastBracketOpen])
		secretValue := strings.TrimSpace(contentLine[lastBracketOpen+1 : lastBracketClose])
		if urlPart != "" && secretValue != "" {
			return fmt.Sprintf("%s - %s", secretValue, urlPart)
		}
	}

	return "" // If parsing fails for all known formats.
}
