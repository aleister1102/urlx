package main

import (
	"strings"
)

func processGospiderLine(line string) string {
	if strings.Contains(line, "[subdomains]") {
		return ""
	}

	var url string
	if index := strings.LastIndex(line, "] - "); index != -1 {
		url = line[index+4:]
	} else {
		url = line
	}

	url = strings.TrimSpace(url)

	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		if stripComponents {
			return stripURLComponents(url)
		}
		return url
	}
	return ""
}
