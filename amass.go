package main

import (
	"regexp"
	"strings"
)

func processAmassLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Regex for MX record lines: e.g., dev.remitly.com (FQDN) --> mx_record --> alt3.aspmx.l.google.com (FQDN)
	mxRegex := regexp.MustCompile(`^(.*?) \(FQDN\) --> mx_record --> (.*?) \(FQDN\)$`)
	matches := mxRegex.FindStringSubmatch(line)

	if len(matches) == 3 {
		sourceFQDN := strings.TrimSpace(matches[1])
		targetFQDN := strings.TrimSpace(matches[2])
		if sourceFQDN != "" && targetFQDN != "" {
			return sourceFQDN + "\n" + targetFQDN // Return both, separated by newline
		} else if sourceFQDN != "" {
			return sourceFQDN
		} else if targetFQDN != "" {
			return targetFQDN
		}
		return "" // Should not happen if regex matched and parts were non-empty
	}

	// For simple FQDN lines or anything else that doesn't match the MX record pattern
	// We assume it's a valid hostname/FQDN if it's not an MX record line.
	// A more robust validation could be added here if needed, e.g. using isValidURL or a similar check.
	return line
}
