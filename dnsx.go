package main

import (
	"net"
	"regexp"
	"strings"
)

// Global flags for dnsx (defined in main.go):
// dnsxExtractA, dnsxExtractAAAA, dnsxExtractCNAME, dnsxExtractMX, dnsxExtractTXT, dnsxExtractNS

var dnsxLineRegex = regexp.MustCompile(`^([^\s]+)\s+\[([A-Z]+)\]\s+\[([^\]]+)\]`)

// processDnsxLine processes a single line of dnsx output.
// Format: domain [TYPE] [value]
// Example: mail.flaticon.com [A] [142.250.71.179]
func processDnsxLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	matches := dnsxLineRegex.FindStringSubmatch(line)
	if len(matches) < 4 {
		return nil
	}

	// matches[1] = domain (not used for extraction)
	recordType := strings.TrimSpace(matches[2])
	value := strings.TrimSpace(matches[3])

	var results []string

	// Check each flag and extract accordingly
	if dnsxExtractA && recordType == "A" {
		if parsedIP := net.ParseIP(value); parsedIP != nil {
			results = append(results, value)
		}
	}

	if dnsxExtractAAAA && recordType == "AAAA" {
		if parsedIP := net.ParseIP(value); parsedIP != nil {
			results = append(results, value)
		}
	}

	if dnsxExtractCNAME && recordType == "CNAME" {
		// For CNAME records, value is the canonical name
		results = append(results, value)
	}

	if dnsxExtractMX && recordType == "MX" {
		// For MX records, value is the mail exchange hostname
		// Only extract if it's a hostname (not an IP)
		if net.ParseIP(value) == nil {
			results = append(results, value)
		}
	}

	if dnsxExtractTXT && recordType == "TXT" {
		// For TXT records, extract the text value
		results = append(results, value)
	}

	if dnsxExtractNS && recordType == "NS" {
		// For NS records, extract the nameserver
		results = append(results, value)
	}

	if dnsxExtractNS && recordType == "SOA" {
		// For SOA records, extract the primary nameserver
		results = append(results, value)
	}

	return results
}

