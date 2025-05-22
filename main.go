package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	toolType        string
	extractRedirect bool
	stripComponents bool
	parallelThreads int
	inputFile       string
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s -t <tool_name> [-r] [-s] [-p <threads>] [-c <threads>] [input_file]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  -t <tool_name> : Specify the tool (httpx, ffuf, dirsearch). Mandatory.")
	fmt.Fprintln(os.Stderr, "  -r             : Extract redirect URLs (if available and tool supports it).")
	fmt.Fprintln(os.Stderr, "  -s             : Strip URL components (query params, fragments).")
	fmt.Fprintln(os.Stderr, "  -p <threads>   : Number of parallel threads (default: 1).")
	fmt.Fprintln(os.Stderr, "  input_file     : Optional input file. If not provided, reads from stdin.")
	os.Exit(1)
}

func main() {
	flag.StringVar(&toolType, "t", "", "Specify the tool (httpx, ffuf, dirsearch)")
	flag.BoolVar(&extractRedirect, "r", false, "Extract redirect URLs")
	flag.BoolVar(&stripComponents, "s", false, "Strip URL components (query params, fragments)")
	flag.IntVar(&parallelThreads, "p", 1, "Number of parallel threads")
	flag.IntVar(&parallelThreads, "c", 1, "Number of concurrent threads (alias for -p)")

	flag.Usage = usage
	flag.Parse()

	if toolType == "" {
		fmt.Fprintln(os.Stderr, "Error: -t <tool_name> is a mandatory argument.")
		usage()
	}

	switch toolType {
	case "httpx", "ffuf", "dirsearch":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch.\n", toolType)
		usage()
	}

	if parallelThreads < 1 {
		fmt.Fprintln(os.Stderr, "Error: -p <threads> must be a positive integer.")
		usage()
	}

	if parallelThreads > 1 {
		fmt.Fprintln(os.Stderr, "Warning: Parallel/concurrent processing (via -p or -c > 1) is specified, but the execution logic is not yet implemented. Processing will be sequential.")
	}

	args := flag.Args()
	if len(args) > 0 {
		inputFile = args[0]
	}

	var reader *bufio.Reader
	var file *os.File
	var err error

	if inputFile != "" && inputFile != "-" {
		file, err = os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Cannot read file '%s': %v\n", inputFile, err)
			os.Exit(1)
		}
		defer file.Close()
		reader = bufio.NewReader(file)
	} else {
		// Check if stdin is a pipe or tty
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			reader = bufio.NewReader(os.Stdin)
		} else if inputFile == "-" {
			reader = bufio.NewReader(os.Stdin)
		} else {
			fmt.Fprintln(os.Stderr, "Error: No input file provided and no data piped to stdin.")
			usage()
		}
	}
	if reader == nil { // Should not happen if logic above is correct
		fmt.Fprintln(os.Stderr, "Error: Input reader was not initialized.")
		os.Exit(1)
	}

	processLines(reader)
}

func processLines(reader *bufio.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		switch toolType {
		case "httpx":
			processHttpxLine(line)
		case "ffuf":
			processFfufLine(line)
		case "dirsearch":
			processDirsearchLine(line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

func isValidURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}
	u, err := url.Parse(toTest)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return true
}

func stripURLComponents(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // Return original if parsing fails
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func processHttpxLine(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return
	}

	urlToProcess := originalURL

	if extractRedirect {
		re := regexp.MustCompile(`\[(https?://[^]]*)\]`)
		matches := re.FindAllStringSubmatch(line, -1)
		if len(matches) > 0 {
			// Get the last match
			lastMatch := matches[len(matches)-1]
			if len(lastMatch) > 1 {
				actualRedirectURL := lastMatch[1]
				if isValidURL(actualRedirectURL) {
					urlToProcess = actualRedirectURL
				}
			}
		}
	}

	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		fmt.Println(finalURL)
	}
}

func processFfufLine(line string) {
	// Skip header lines starting with "FUZZ,"
	if strings.HasPrefix(line, "FUZZ,") {
		return
	}

	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return
	}

	var originalURL, redirectCandidate string

	valAtIdx1 := parts[1]
	var valAtIdx2, valAtIdx3 string
	if len(parts) > 2 {
		valAtIdx2 = parts[2]
	}
	if len(parts) > 3 {
		valAtIdx3 = parts[3]
	}

	if isValidURL(valAtIdx1) {
		// Format: FUZZ_KEYWORD,URL,REDIRECT_URL?,...
		originalURL = valAtIdx1
		if valAtIdx2 != "" && isValidURL(valAtIdx2) {
			redirectCandidate = valAtIdx2
		}
	} else if valAtIdx2 != "" && isValidURL(valAtIdx2) {
		// Format: FUZZ_KEYWORD,METHOD,URL,REDIRECT_URL?,...
		originalURL = valAtIdx2
		if valAtIdx3 != "" && isValidURL(valAtIdx3) {
			redirectCandidate = valAtIdx3
		}
	} else {
		return // Not a recognizable ffuf data line
	}

	if originalURL == "" {
		return
	}

	urlToProcess := originalURL
	if extractRedirect && redirectCandidate != "" {
		urlToProcess = redirectCandidate
	}

	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		fmt.Println(finalURL)
	}
}

func processDirsearchLine(line string) {
	if strings.HasPrefix(line, "#") {
		return
	}

	fields := strings.Fields(line)
	// Expected format: STATUS SIZE URL ... [-> REDIRECTS TO: REDIRECT_URL]
	// We need at least 3 fields for STATUS, SIZE, URL
	if len(fields) < 3 {
		return
	}

	// The URL is usually the 3rd field (index 2)
	originalURL := fields[2]
	if !isValidURL(originalURL) {
		// If the third field isn't a URL, this line isn't what we expect.
		// The bash script tries to read status, size, initial_url_part.
		// Let's try to be a bit more robust by finding the first valid URL.
		foundURL := ""
		for _, field := range fields {
			if isValidURL(field) {
				foundURL = field
				break
			}
		}
		if foundURL == "" {
			return
		}
		originalURL = foundURL
	}

	var redirectURL string
	redirectMarker := "-> REDIRECTS TO:"
	lineStr := strings.Join(fields, " ") // Rejoin for easier searching of the marker phrase

	if idx := strings.Index(lineStr, redirectMarker); idx != -1 {
		potentialRedirect := strings.TrimSpace(lineStr[idx+len(redirectMarker):])
		// The redirect URL might be followed by other information, so take the first space-separated token.
		redirectParts := strings.Fields(potentialRedirect)
		if len(redirectParts) > 0 && isValidURL(redirectParts[0]) {
			redirectURL = redirectParts[0]
		}
	}

	urlToProcess := originalURL
	if extractRedirect && redirectURL != "" {
		urlToProcess = redirectURL
	}

	if urlToProcess == "" { // Should not happen if originalURL was valid
		return
	}

	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		fmt.Println(finalURL)
	}
}
