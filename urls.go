package main

import (
	"net/url"
	"strings"
)

// processUrlsLine xử lý một dòng URL từ file input
// Validate URL và có thể áp dụng các filter/transform
func processUrlsLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Bỏ qua comments và empty lines
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return ""
	}

	hasScheme := strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")

	// Nếu có scheme khác http/https thì reject
	if strings.Contains(line, "://") && !hasScheme {
		return ""
	}

	// Tự động thêm scheme nếu chưa có
	if !hasScheme {
		// Kiểm tra xem có phải là domain/hostname hợp lệ không trước khi thêm scheme
		if !strings.Contains(line, ".") || strings.Contains(line, " ") {
			return ""
		}
		line = "https://" + line
	}

	// Validate URL
	parsedURL, err := url.Parse(line)
	if err != nil {
		return ""
	}

	// Kiểm tra scheme hợp lệ
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return ""
	}

	// Kiểm tra hostname không rỗng và hợp lệ
	if parsedURL.Hostname() == "" {
		return ""
	}

	// Nếu stripComponents được set, loại bỏ path, query, fragment
	if stripComponents {
		parsedURL.Path = ""
		parsedURL.RawQuery = ""
		parsedURL.Fragment = ""
		return parsedURL.String()
	}

	// Trả về URL đã được normalize (có scheme)
	return parsedURL.String()
}
