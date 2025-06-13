package main

import (
	"net"
	"strings"
)

// Các biến cờ dnsExtractA, dnsExtractCNAME, dnsExtractMX được định nghĩa toàn cục trong main.go
// và được sử dụng ở đây để quyết định cách xử lý dòng.

// processDnsLine xử lý một dòng output từ tool dns.
// Nó trả về một slice các chuỗi dựa trên các cờ được kích hoạt.
func processDnsLine(line string) []string {
	parts := strings.Split(line, ",")
	if len(parts) < 4 { // Cần ít nhất 4 phần: QueriedName, Type, SomeValue, TargetValue
		return nil
	}

	recordType := strings.TrimSpace(parts[1])
	// parts[3] là giá trị mục tiêu cho các bản ghi A, AAAA, CNAME, và MX (tên máy chủ của mail exchanger).
	value := strings.TrimSpace(parts[3])

	var results []string

	// Nếu cờ -a được kích hoạt, nó sẽ được ưu tiên cho việc tạo output từ hàm này.
	// Các cờ khác (-cname, -mx) sẽ bị bỏ qua nếu -a được đặt,
	// vì trích xuất IP là một chế độ riêng biệt.
	if dnsExtractA {
		if recordType == "A" || recordType == "AAAA" {
			if parsedIP := net.ParseIP(value); parsedIP != nil {
				results = append(results, value)
			}
		}
		// Việc sắp xếp và loại bỏ trùng lặp IP được xử lý trong goroutine output của main.go.
		return results
	}

	// Nếu -a không được kích hoạt, xử lý các cờ -cname và -mx.
	// main.go sẽ đảm bảo rằng một trong ba tùy chọn (-a, -cname, -mx) được chọn.

	if dnsExtractCNAME && recordType == "CNAME" {
		// Đối với bản ghi CNAME, 'value' (parts[3]) là tên canonical.
		results = append(results, value)
	}

	if dnsExtractMX && recordType == "MX" {
		// Đối với bản ghi MX, 'value' (parts[3]) phải là tên máy chủ của mail exchange.
		// Chúng ta chỉ trích xuất nó nếu đó là một tên máy chủ hợp lệ (tức là không phải địa chỉ IP).
		if net.ParseIP(value) == nil {
			results = append(results, value)
		}
	}
	return results
}
