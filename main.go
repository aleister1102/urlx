package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	toolType          string
	extractRedirect   bool
	stripComponents   bool
	extractDomainOnly bool
	parallelThreads   int
	inputFile         string
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s -t <tool_name> [-r] [-s] [-d] [-p <threads>] [-c <threads>] [input_file]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  -t <tool_name> : Specify the tool (httpx, ffuf, dirsearch, amass). Mandatory.")
	fmt.Fprintln(os.Stderr, "  -r             : Extract redirect URLs (if available and tool supports it).")
	fmt.Fprintln(os.Stderr, "  -s             : Strip URL components (query params, fragments).")
	fmt.Fprintln(os.Stderr, "  -d             : Extract only the domain from URLs.")
	fmt.Fprintln(os.Stderr, "  -p <threads>   : Number of parallel threads (default: 1).")
	fmt.Fprintln(os.Stderr, "  -c <threads>   : Number of concurrent threads (alias for -p)")
	fmt.Fprintln(os.Stderr, "  input_file     : Optional input file. If not provided, reads from stdin.")
	os.Exit(1)
}

func getDomain(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func main() {
	flag.StringVar(&toolType, "t", "", "Specify the tool (httpx, ffuf, dirsearch, amass)")
	flag.BoolVar(&extractRedirect, "r", false, "Extract redirect URLs")
	flag.BoolVar(&stripComponents, "s", false, "Strip URL components (query params, fragments)")
	flag.BoolVar(&extractDomainOnly, "d", false, "Extract only the domain from URLs")
	flag.IntVar(&parallelThreads, "p", 1, "Number of parallel threads")
	flag.IntVar(&parallelThreads, "c", 1, "Number of concurrent threads (alias for -p)")

	flag.Usage = usage
	flag.Parse()

	if toolType == "" {
		fmt.Fprintln(os.Stderr, "Error: -t <tool_name> is a mandatory argument.")
		usage()
	}

	switch toolType {
	case "httpx", "ffuf", "dirsearch", "amass":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch, amass.\n", toolType)
		usage()
	}

	if parallelThreads < 1 {
		fmt.Fprintln(os.Stderr, "Error: -p or -c <threads> must be a positive integer.")
		usage()
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

	linesChan := make(chan string, parallelThreads)
	resultsChan := make(chan string, parallelThreads)
	var wg sync.WaitGroup
	var outputWg sync.WaitGroup

	// Input Goroutine
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			linesChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		}
		close(linesChan)
	}()

	// Worker Goroutines
	for i := 0; i < parallelThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				if line == "" {
					continue
				}
				var result string
				switch toolType {
				case "httpx":
					result = processHttpxLine(line)
				case "ffuf":
					result = processFfufLine(line)
				case "dirsearch":
					result = processDirsearchLine(line)
				case "amass":
					result = processAmassLine(line)
				}
				if result != "" {
					if extractDomainOnly {
						domain := getDomain(result)
						if domain != "" {
							resultsChan <- domain
						}
					} else {
						resultsChan <- result
					}
				}
			}
		}()
	}

	// Output/Printer Goroutine
	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		for result := range resultsChan {
			fmt.Println(result)
		}
	}()

	// Waiting and Cleanup
	wg.Wait()          // Wait for all workers to finish processing
	close(resultsChan) // Signal to the printer goroutine that no more results are coming
	outputWg.Wait()    // Wait for the printer goroutine to finish printing all results
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

func processHttpxLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ""
	}
	originalURL := parts[0]

	if !isValidURL(originalURL) {
		return ""
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
		return finalURL
	}
	return ""
}

func processFfufLine(line string) string {
	// Skip header lines starting with "FUZZ,"
	if strings.HasPrefix(line, "FUZZ,") {
		return ""
	}

	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return ""
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
		return "" // Not a recognizable ffuf data line
	}

	if originalURL == "" {
		return ""
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
		return finalURL
	}
	return ""
}

func processDirsearchLine(line string) string {
	if strings.HasPrefix(line, "#") {
		return ""
	}

	fields := strings.Fields(line)
	// Expected format: STATUS SIZE URL ... [-> REDIRECTS TO: REDIRECT_URL]
	// We need at least 3 fields for STATUS, SIZE, URL
	if len(fields) < 3 {
		return ""
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
			return ""
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
		return ""
	}

	finalURL := urlToProcess
	if stripComponents {
		finalURL = stripURLComponents(urlToProcess)
	}

	if finalURL != "" {
		return finalURL
	}
	return ""
}

func processAmassLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Regex for MX record lines: e.g., dev.remitly.com (FQDN) --> mx_record --> alt3.aspmx.l.google.com (FQDN)
	mxRegex := regexp.MustCompile(`^(.*?) \(FQDN\) --> mx_record --> (.*?) \(FQDN\)$`)
	matches := mxRegex.FindStringSubmatch(line)

	if len(matches) == 3 {
		sourceFQDN := strings.TrimSpace(matches[1])
		targetFQDN := strings.TrimSpace(matches[2])
		if sourceFQDN != "" && targetFQDN != "" {
			return sourceFQDN + "\n" + targetFQDN // Return both, separated by newline
		} else if sourceFQDN != "" {
			return sourceFQDN
		} else if targetFQDN != "" {
			return targetFQDN
		}
		return "" // Should not happen if regex matched and parts were non-empty
	}

	// For simple FQDN lines or anything else that doesn't match the MX record pattern
	// We assume it's a valid hostname/FQDN if it's not an MX record line.
	// A more robust validation could be added here if needed, e.g. using isValidURL or a similar check.
	return line
}
