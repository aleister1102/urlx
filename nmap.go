package main

import (
	"fmt"
	"net"
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
	if strings.HasPrefix(line, "Nmap scan report for ") {
		reportTarget := strings.TrimSpace(strings.TrimPrefix(line, "Nmap scan report for "))

		// Regex to find potential IP-like strings (alphanumeric, '.', ':', '%').
		// This is intentionally broad to capture various formats including IPv6 with scope IDs.
		// We will validate them using net.ParseIP.
		// It tries to match sequences that can form an IP address, including hostnames that might precede an IP in parentheses.
		// The primary goal is to extract the actual IP address string part.
		// Example: "some.hostname (1.2.3.4)" -> extracts "1.2.3.4"
		// Example: "2600:9000::1" -> extracts "2600:9000::1"
		// Example: "my.machine.local" -> might extract "my.machine.local", which net.ParseIP will reject unless it's a valid IP literal.
		candidateRegex := regexp.MustCompile(`([a-zA-Z0-9\.:%]+(?:\[[a-zA-Z0-9%]+\])?)`) // handles IPv6 with scope ID like fe80::1%lo0
		potentialIPs := candidateRegex.FindAllString(reportTarget, -1)

		var foundValidIP string
		for _, potentialIP := range potentialIPs {
			// For IPv6, scope ID (e.g., %eth0) needs to be removed for net.ParseIP to work correctly
			// unless it's a link-local address where it's part of the address.
			// However, net.ParseIP handles common IPv6 forms well.
			// Let's try parsing directly. If it contains '%', net.ParseIP might fail for global addresses.
			// A more robust way is to split by '%' and parse the first part if needed, but for nmap output,
			// the direct IP string is usually clean or net.ParseIP can handle it.

			// Trim potential surrounding parentheses or other non-IP characters if the regex was too greedy.
			// This is a bit of a heuristic; ideally, the regex is precise or nmap output is consistent.
			// For now, let's assume regex captures reasonably clean IP candidates.
			parsedIP := net.ParseIP(potentialIP)
			if parsedIP != nil {
				foundValidIP = potentialIP // Store the string representation that was successfully parsed
			}
		}

		if foundValidIP != "" {
			newIPContext = foundValidIP
		} else {
			// No valid IP found in the report line, keep the old IP context
			// This means we might be parsing a hostname-only report line.
			return outputs, currentIP // Return currentIP
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

		// Apply -o filter first: if nmapFilterOpenPorts is true, only process if status is "open"
		if nmapFilterOpenPorts && status != "open" {
			return outputs, newIPContext // Skip this line if -o is active and port is not open
		}

		var formattedOutput string
		// Apply -p format if nmapExportIPPort is true
		if nmapExportIPPort {
			formattedOutput = fmt.Sprintf("%s:%s", newIPContext, port)
		} else {
			// Default full format if -p is not active
			formattedOutput = fmt.Sprintf("[%s] - [%s] - [%s] - [%s] - [%s]", newIPContext, port, service, version, status)
		}
		outputs = append(outputs, formattedOutput)
	}

	return outputs, newIPContext
}
