package main

import (
	"fmt"
	"regexp"
	"strings"
)

// processNmapLine processes a single line of nmap output.
// It maintains a currentIP context because nmap output is multi-line per IP.
// Returns a slice of formatted port info strings and the new IP context.
func processNmapLine(line string, currentIP string) ([]string, string) {
	line = strings.TrimSpace(line)
	var outputs []string
	newIPContext := currentIP

	// Regex to find an IP address in lines like "Nmap scan report for ..."
	// It will capture the last IP-like pattern found on the line.
	if strings.HasPrefix(line, "Nmap scan report for ") {
		reportTarget := strings.TrimSpace(strings.TrimPrefix(line, "Nmap scan report for "))
		ipExtractRegex := regexp.MustCompile(`(([0-9]{1,3}\.){3}[0-9]{1,3})`)
		foundIPs := ipExtractRegex.FindAllString(reportTarget, -1)

		if len(foundIPs) > 0 {
			newIPContext = foundIPs[len(foundIPs)-1] // Use the last IP found on the line
		} else {
			// No valid IP found in the report line, keep the old IP context
			// This means we might be parsing a hostname-only report line which we can't use for IP-based port listing as per req.
			return outputs, currentIP // Return currentIP, not newIPContext which might be a hostname
		}
		return outputs, newIPContext // IP context updated, no port info from this specific line
	}

	// If newIPContext (our current IP for context) is not set, we can't process port lines effectively.
	if newIPContext == "" {
		return outputs, newIPContext
	}

	// Regex for port line: PORT STATE SERVICE VERSION
	// Example: 22/tcp  open   ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
	// Example: 80/tcp  closed http
	// Example: 53/udp  open|filtered domain
	// Captures: 1:Port, 2:State, 3:Service, 4:Version (optional)
	portRegex := regexp.MustCompile(`^(\d+)/(?:tcp|udp|sctp|icmp)\s+([^\s]+)\s+([^\s]+)(?:\s+(.*))?$`)
	portMatch := portRegex.FindStringSubmatch(line)

	if len(portMatch) >= 4 { // Need at least Port, State, Service
		port := portMatch[1]
		status := portMatch[2]
		service := portMatch[3]
		version := "N/A"                                                 // Default version
		if len(portMatch) > 4 && strings.TrimSpace(portMatch[4]) != "" { // Check if version group exists and is non-empty after trim
			version = strings.TrimSpace(portMatch[4])
		}

		formattedOutput := fmt.Sprintf("[%s] - [%s] - [%s] - [%s] - [%s]", newIPContext, port, service, version, status)
		outputs = append(outputs, formattedOutput)
	}

	return outputs, newIPContext
}
