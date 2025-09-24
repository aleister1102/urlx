package main

import (
	"net"
	"strings"
)

// processMassdnsLine xử lý một dòng output từ massdns.
// Format: subdomain.domain.com. A 1.2.3.4
// hoặc: subdomain.domain.com. CNAME target.com.
// Hàm này sẽ extract subdomain hoặc IP có A record khác localhost/invalid IPs
func processMassdnsLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	// Format: subdomain.domain.com. A/CNAME target
	subdomain := strings.TrimSuffix(parts[0], ".")
	recordType := parts[1]
	target := parts[2]

	var results []string

	// Chỉ xử lý A records
	if recordType == "A" {
		// Kiểm tra xem target có phải là IP hợp lệ không
		ip := net.ParseIP(target)
		if ip == nil {
			return nil
		}

		// Filter out localhost và invalid IPs
		if isValidPublicIP(target) {
			results = append(results, subdomain)
		}
	}

	return results
}

// processMassdnsLineForIP xử lý một dòng output từ massdns để extract IP.
// Format: subdomain.domain.com. A 1.2.3.4
// Hàm này sẽ extract IP có A record khác localhost/invalid IPs
func processMassdnsLineForIP(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	// Format: subdomain.domain.com. A/CNAME target
	recordType := parts[1]
	target := parts[2]

	var results []string

	// Chỉ xử lý A records
	if recordType == "A" {
		// Kiểm tra xem target có phải là IP hợp lệ không
		ip := net.ParseIP(target)
		if ip == nil {
			return nil
		}

		// Filter out localhost và invalid IPs
		if isValidPublicIP(target) {
			results = append(results, target)
		}
	}

	return results
}

// isValidPublicIP kiểm tra xem IP có phải là public IP hợp lệ không
// Loại bỏ localhost, private IPs và các IP không hợp lệ
func isValidPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Loại bỏ các IP không hợp lệ/localhost
	invalidIPs := []string{
		"0.0.0.0",
		"127.0.0.1",
	}

	for _, invalidIP := range invalidIPs {
		if ipStr == invalidIP {
			return false
		}
	}

	// Kiểm tra private IP ranges
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return false
	}

	// Loại bỏ multicast và link-local
	if ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}

	// Kiểm tra reserved ranges
	// 10.0.0.0/8
	if ipv4 := ip.To4(); ipv4 != nil {
		if ipv4[0] == 10 {
			return false
		}
		// 172.16.0.0/12
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return false
		}
		// 192.168.0.0/16
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return false
		}
		// 169.254.0.0/16 (link-local)
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return false
		}
	}

	return true
}