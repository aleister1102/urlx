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

	// Ignore lines about ASN/Netblock entirely
	if strings.Contains(line, "(ASN)") || strings.Contains(line, "(Netblock)") || strings.Contains(line, "(RIROrganization)") {
		return ""
	}

	// General amass edge pattern: "<src> (FQDN) --> <record_type> --> <dst> (<Kind>)"
	// Kind is usually FQDN or IPAddress
	edgeRegex := regexp.MustCompile(`^\s*(.*?)\s*\(FQDN\)\s*-->\s*[a-z_]+\s*-->\s*(.*?)\s*\((FQDN|IPAddress)\)\s*$`)
	if m := edgeRegex.FindStringSubmatch(line); len(m) == 4 {
		src := strings.TrimSpace(m[1])
		dst := strings.TrimSpace(m[2])
		dstKind := m[3]

		// Always emit the source FQDN
		// Emit destination only if it is also an FQDN (skip IPs)
		if dstKind == "FQDN" && dst != "" {
			if src != "" {
				return src + "\n" + dst
			}
			return dst
		}
		return src
	}

	// Simple node line pattern: "<fqdn> (FQDN)"
	nodeRegex := regexp.MustCompile(`^\s*(.*?)\s*\(FQDN\)\s*$`)
	if m := nodeRegex.FindStringSubmatch(line); len(m) == 2 {
		fqdn := strings.TrimSpace(m[1])
		return fqdn
	}

	// Anything else is not a hostname we care about
	return ""
}
