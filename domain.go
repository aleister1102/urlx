package main

// processDomainToolLine trích xuất domain/IP từ một chuỗi URL.
// Nó sử dụng lại hàm getDomain từ main.go (được giả định là có thể truy cập trong cùng package).
func processDomainToolLine(line string) string {
	// Dòng đầu vào được cho là một URL hoặc một cái gì đó mà getDomain có thể xử lý.
	// Nếu getDomain yêu cầu URL phải có scheme, và line không có,
	// getDomain sẽ tự động thêm "http://" vào trước khi phân tích.
	domainOrIP := getDomain(line)
	if domainOrIP != "" {
		return domainOrIP
	}
	return "" // Trả về chuỗi rỗng nếu không trích xuất được gì
}
