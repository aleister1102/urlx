package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	extractRedirect      bool
	stripComponents      bool
	extractDomainOnly    bool
	filterIPHost         bool
	numThreads           int
	nmapExportIPPort     bool
	nmapFilterOpenPorts  bool
	dnsxExtractA         bool
	dnsxExtractAAAA      bool
	dnsxExtractCNAME     bool
	dnsxExtractMX        bool
	dnsxExtractTXT       bool
	dnsxExtractNS        bool
	ffufProcessFolder    bool
	filterStatusCodes    string
	filterContentTypes   string
	filterContentLengths string
	matchStatusCodes     string
	matchContentTypes    string
	matchContentLengths  string
	preserveContent      bool
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <tool_name> [options] [input_file]\n", os.Args[0])

	fmt.Fprintln(os.Stderr, "Available Tools:")
	fmt.Fprintln(os.Stderr, "  amass          Processes amass intel/enum output. Extracts hostnames.")
	fmt.Fprintln(os.Stderr, "  dirsearch      Processes dirsearch output. Extracts found paths and combines with target.")
	fmt.Fprintln(os.Stderr, "  dnsx           Processes dnsx output. Extracts DNS records (A, AAAA, CNAME, MX, TXT, NS).")
	fmt.Fprintln(os.Stderr, "  ffuf           Processes ffuf output. Parses URLs from successful results.")
	fmt.Fprintln(os.Stderr, "  gospider       Processes gospider output. Extracts URLs from scan results.")
	fmt.Fprintln(os.Stderr, "  httpx          Processes httpx output. Expects URLs or lines containing URLs.")
	fmt.Fprintln(os.Stderr, "  nmap           Processes nmap output (standard -oN or -oG). Extracts IP, port, service, version.")
	fmt.Fprintln(os.Stderr, "  nuclei         Processes nuclei output. Extracts URLs from scan results.")
	fmt.Fprintln(os.Stderr, "  urls           Processes a list of URLs from file. Validates and filters URLs.")
	fmt.Fprintln(os.Stderr, "Common Options:")
	fmt.Fprintln(os.Stderr, "  -r             Extract redirect URLs (if tool output provides redirect info, e.g., httpx, ffuf).")
	fmt.Fprintln(os.Stderr, "  -s             Strip URL components (path, query parameters and fragments) before further processing or output.")
	fmt.Fprintln(os.Stderr, "  -d             Extract domain/subdomain hostnames with port (excludes IPs, strips scheme/path/query/fragment).")
	fmt.Fprintln(os.Stderr, "  -ip            Filters for URLs with an IP host and extracts the IP address and port (e.g., 1.2.3.4:443).")
	fmt.Fprintln(os.Stderr, "  -t <threads>   Number of concurrent processing threads (default: 1).")

	fmt.Fprintln(os.Stderr, "Nmap Specific Options ('nmap' tool only):")
	fmt.Fprintln(os.Stderr, "  -p             Export IP and port pairs (e.g., 192.168.1.1:80). Overrides default nmap format.")
	fmt.Fprintln(os.Stderr, "  -o             Filter for open ports only. Applied before -p if both are used.")

	fmt.Fprintln(os.Stderr, "Dnsx Specific Options ('dnsx' tool only - can combine multiple):")
	fmt.Fprintln(os.Stderr, "  -a             Extract A records (IPv4 addresses).")
	fmt.Fprintln(os.Stderr, "  -aaaa          Extract AAAA records (IPv6 addresses).")
	fmt.Fprintln(os.Stderr, "  -cname         Extract CNAME records (canonical names).")
	fmt.Fprintln(os.Stderr, "  -mx            Extract MX records (mail exchange hostnames).")
	fmt.Fprintln(os.Stderr, "  -txt           Extract TXT records.")
	fmt.Fprintln(os.Stderr, "  -ns            Extract NS and SOA records (nameservers).")

	fmt.Fprintln(os.Stderr, "Filtering & Matching Options ('ffuf', 'httpx', 'dirsearch'):")
	fmt.Fprintln(os.Stderr, "  -f             Process all files in the current directory as ffuf input (ffuf only).")
	fmt.Fprintln(os.Stderr, "  -fc <codes>    Filter out responses with these status codes (e.g., 403,404).")
	fmt.Fprintln(os.Stderr, "  -fcl <lengths> Filter out responses with these content lengths (e.g., 0,123).")
	fmt.Fprintln(os.Stderr, "  -fct <types>   Filter out responses with these content types (e.g., text/html) (ffuf, httpx only).")
	fmt.Fprintln(os.Stderr, "  -mc <codes>    Match responses with these status codes (e.g., 200,302).")
	fmt.Fprintln(os.Stderr, "  -mcl <lengths> Match responses with these content lengths (e.g., 512,1024).")
	fmt.Fprintln(os.Stderr, "  -mct <types>   Match responses with these content types (e.g., application/json) (ffuf, httpx only).")
	fmt.Fprintln(os.Stderr, "  -pc            Preserve original line content on match (instead of extracting URL) (ffuf, httpx, dirsearch).")

	fmt.Fprintln(os.Stderr, "Input:")
	fmt.Fprintln(os.Stderr, "  [input_file]   Optional. File to read input from. If omitted or '-', reads from stdin.")
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
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: <tool_name> is mandatory.")
		usage()
	}

	toolType := os.Args[1]
	argsForFlags := os.Args[2:]

	cmdFlags := flag.NewFlagSet(toolType, flag.ExitOnError)
	cmdFlags.Usage = usage

	cmdFlags.BoolVar(&extractRedirect, "r", false, "Extract redirect URLs")
	cmdFlags.BoolVar(&stripComponents, "s", false, "Strip URL components")
	cmdFlags.BoolVar(&extractDomainOnly, "d", false, "Extract domain/subdomain hostnames with port (excludes IPs)")
	cmdFlags.BoolVar(&filterIPHost, "ip", false, "Filter for URLs with an IP host and extract IP:port.")
	cmdFlags.IntVar(&numThreads, "t", 1, "Number of concurrent threads")

	cmdFlags.BoolVar(&nmapExportIPPort, "p", false, "Export IP and port pairs (nmap only)")
	cmdFlags.BoolVar(&nmapFilterOpenPorts, "o", false, "Filter for open ports only (nmap only)")

	cmdFlags.BoolVar(&dnsxExtractA, "a", false, "Extract A records (dnsx only)")
	cmdFlags.BoolVar(&dnsxExtractAAAA, "aaaa", false, "Extract AAAA records (dnsx only)")
	cmdFlags.BoolVar(&dnsxExtractCNAME, "cname", false, "Extract CNAME records (dnsx only)")
	cmdFlags.BoolVar(&dnsxExtractMX, "mx", false, "Extract MX records (dnsx only)")
	cmdFlags.BoolVar(&dnsxExtractTXT, "txt", false, "Extract TXT records (dnsx only)")
	cmdFlags.BoolVar(&dnsxExtractNS, "ns", false, "Extract NS/SOA records (dnsx only)")

	cmdFlags.BoolVar(&ffufProcessFolder, "f", false, "Process all files in current directory (ffuf only)")
	cmdFlags.StringVar(&filterStatusCodes, "fc", "", "Comma-separated status codes to filter out (ffuf, httpx only)")
	cmdFlags.StringVar(&filterContentTypes, "fct", "", "Comma-separated content types to filter out (ffuf, httpx only)")
	cmdFlags.StringVar(&filterContentLengths, "fcl", "", "Comma-separated content lengths to filter out (ffuf, httpx only)")
	cmdFlags.StringVar(&matchStatusCodes, "mc", "", "Comma-separated status codes to match (ffuf, httpx only)")
	cmdFlags.StringVar(&matchContentTypes, "mct", "", "Comma-separated content types to match (ffuf, httpx only)")
	cmdFlags.StringVar(&matchContentLengths, "mcl", "", "Comma-separated content lengths to match (ffuf, httpx only)")
	cmdFlags.BoolVar(&preserveContent, "pc", false, "Preserve original line content on match (httpx, ffuf only)")

	err := cmdFlags.Parse(argsForFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\\n", err)
		usage()
	}

	switch toolType {
	case "httpx", "ffuf", "dirsearch", "amass", "nmap", "dnsx", "nuclei", "gospider", "urls":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch, amass, nmap, dnsx, nuclei, gospider, urls.\n", toolType)
		usage()
	}

	if toolType == "dnsx" && !dnsxExtractA && !dnsxExtractAAAA && !dnsxExtractCNAME && !dnsxExtractMX && !dnsxExtractTXT && !dnsxExtractNS {
		fmt.Fprintln(os.Stderr, "Error: For 'dnsx' tool, you must specify at least one of -a, -aaaa, -cname, -mx, -txt, or -ns options.")
		usage()
	}

	if numThreads < 1 {
		fmt.Fprintln(os.Stderr, "Error: -t <threads> must be a positive integer.")
		usage()
	}

	var inputFile string
	remainingArgs := cmdFlags.Args() // Args not parsed as flags
	if len(remainingArgs) > 0 {
		inputFile = remainingArgs[0]
	} else {
		inputFile = ""
	}

	// Input validation before starting goroutines
	if !(toolType == "ffuf" && ffufProcessFolder) {
		// Standard mode: single input file or stdin
		if inputFile == "" { // No file argument provided
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 { // And stdin is a TTY (no pipe)
				fmt.Fprintln(os.Stderr, "Error: No input file specified and no data piped to stdin.")
				usage() // Exits
			}
		} else if inputFile != "-" { // A specific file is provided (not stdin via "-")
			if _, err := os.Stat(inputFile); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: Input file '%s' not found.\n", inputFile)
				os.Exit(1)
			}
		}
		// If inputFile == "-", stdin will be used, which is fine.
	} else { // ffuf -f mode
		if inputFile != "" && inputFile != "-" {
			fmt.Fprintf(os.Stderr, "Warning: Input file argument '%s' is ignored when -f (process folder) option is used with ffuf.\n", inputFile)
		}
		// Further validation for ffuf -f (e.g., directory readability) can be done in the goroutine.
	}

	linesChan := make(chan string, 1000)
	resultsChan := make(chan string, 1000)
	var wg sync.WaitGroup
	var outputWg sync.WaitGroup

	// Producer goroutine: reads input and sends to linesChan
	go func() {
		defer close(linesChan)

		if toolType == "ffuf" && ffufProcessFolder {
			// Process all files in current directory
			cwdFiles, err := os.ReadDir(".")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading current directory for ffuf -f: %v\n", err)
				return // Exit goroutine, linesChan will be closed
			}

			foundFiles := false
			for _, dirEntry := range cwdFiles {
				if !dirEntry.IsDir() {
					filePath := dirEntry.Name()
					file, err := os.Open(filePath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error opening file '%s' for ffuf: %v\n", filePath, err)
						continue // Skip this file
					}
					// fmt.Fprintf(os.Stderr, "INFO: Processing file '%s' for ffuf -f mode.\n", filePath) // Debug

					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						linesChan <- scanner.Text()
					}
					if err := scanner.Err(); err != nil {
						fmt.Fprintf(os.Stderr, "Error reading from file '%s' for ffuf: %v\n", filePath, err)
					}
					file.Close() // Close the file
					foundFiles = true
				}
			}
			if !foundFiles {
				fmt.Fprintln(os.Stderr, "Warning: ffuf -f: No regular files found in the current directory.")
			}

		} else {
			// Standard input: single file or stdin, as validated before starting this goroutine
			var reader *bufio.Reader
			var fileToClose *os.File // Variable to hold the file if opened, so it can be closed

			if inputFile != "" && inputFile != "-" { // Specific input file
				var openErr error
				fileToClose, openErr = os.Open(inputFile)
				if openErr != nil {
					// This should have been caught by pre-flight check, but as a safeguard:
					fmt.Fprintf(os.Stderr, "Error: Cannot open input file '%s': %v\n", inputFile, openErr)
					return // Exit goroutine
				}
				defer fileToClose.Close() // Close when goroutine exits
				reader = bufio.NewReader(fileToClose)
			} else { // Stdin (either no inputFile, or inputFile == "-")
				reader = bufio.NewReader(os.Stdin)
			}

			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				linesChan <- scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			}
		}
	}()

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var currentNmapIPContext string
			for line := range linesChan {
				if line == "" {
					continue
				}
				var processedOutputs []string
				switch toolType {
				case "httpx":
					result := processHttpxLine(line, filterStatusCodes, filterContentTypes, filterContentLengths, matchStatusCodes, matchContentTypes, matchContentLengths, preserveContent)
					if result != "" {
						processedOutputs = append(processedOutputs, result)
					}
				case "ffuf":
					result := processFfufLine(line, filterStatusCodes, filterContentTypes, filterContentLengths, matchStatusCodes, matchContentTypes, matchContentLengths, preserveContent)
					if result != "" {
						processedOutputs = append(processedOutputs, result)
					}
				case "dirsearch":
					result := processDirsearchLine(line, filterStatusCodes, filterContentLengths, matchStatusCodes, matchContentLengths, preserveContent)
					if result != "" {
						processedOutputs = append(processedOutputs, result)
					}
				case "amass":
					result := processAmassLine(line)
					if result != "" {
						potentialHostnames := strings.Split(result, "\\n")
						for _, hostname := range potentialHostnames {
							hostname = strings.TrimSpace(hostname)
							if hostname != "" {
								processedOutputs = append(processedOutputs, hostname)
							}
						}
					}
				case "nmap":
					var nmapResults []string
					nmapResults, currentNmapIPContext = processNmapLine(line, currentNmapIPContext)
					processedOutputs = append(processedOutputs, nmapResults...)
				case "dnsx":
					dnsxResults := processDnsxLine(line)
					processedOutputs = append(processedOutputs, dnsxResults...)
				case "nuclei":
					nucleiResult := processNucleiLine(line)
					if nucleiResult != "" {
						processedOutputs = append(processedOutputs, nucleiResult)
					}
				case "gospider":
					gospiderResult := processGospiderLine(line)
					if gospiderResult != "" {
						processedOutputs = append(processedOutputs, gospiderResult)
					}
				case "urls":
					urlsResult := processUrlsLine(line)
					if urlsResult != "" {
						processedOutputs = append(processedOutputs, urlsResult)
					}
				}
				for _, outputItem := range processedOutputs {
					if outputItem == "" {
						continue
					}

					if preserveContent && (toolType == "httpx" || toolType == "ffuf") {
						resultsChan <- outputItem
						continue
					}

					if filterIPHost {
						ipWithPort := getIPHostWithPort(outputItem, toolType)
						if ipWithPort != "" {
							resultsChan <- ipWithPort
						}
						continue
					}

					if extractDomainOnly {
						domainURL := getDomainHostWithPort(outputItem, toolType)
						if domainURL != "" {
							resultsChan <- domainURL
						}
						continue
					}

					resultsChan <- outputItem
				}
			}
		}()
	}

	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		if toolType == "dnsx" && (dnsxExtractA || dnsxExtractAAAA) {
			var allIPs []string
			for result := range resultsChan {
				allIPs = append(allIPs, result)
			}
			sort.Strings(allIPs)
			uniqueIPs := make([]string, 0, len(allIPs))
			if len(allIPs) > 0 {
				uniqueIPs = append(uniqueIPs, allIPs[0])
				for i := 1; i < len(allIPs); i++ {
					if allIPs[i] != allIPs[i-1] {
						uniqueIPs = append(uniqueIPs, allIPs[i])
					}
				}
			}
			for _, ip := range uniqueIPs {
				fmt.Println(ip)
			}
		} else {
			for result := range resultsChan {
				fmt.Println(result)
			}
		}
	}()

	wg.Wait()
	close(resultsChan)
	outputWg.Wait()
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
		return rawURL
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// getDomainHostWithPort extracts the host:port from a tool's output line if the host is NOT an IP (i.e., is a domain/subdomain).
func getDomainHostWithPort(outputItem string, toolType string) string {
	var urlToParse string
	// For different tools, we extract the URL part first
	switch toolType {
	case "nmap":
		if strings.Contains(outputItem, " - ") {
			// Full format: [IP] - ...
			ipParts := strings.SplitN(outputItem, " - ", 2)
			if len(ipParts) > 0 {
				host := strings.Trim(ipParts[0], "[]")
				if !isIP(host) {
					return host // Return the domain/hostname
				}
			}
		} else {
			// IP:port format from -p flag
			host, _, err := net.SplitHostPort(outputItem)
			if err == nil && !isIP(host) {
				return outputItem // Return full host:port if it's a domain
			}
		}
		return ""
	default: // httpx, ffuf, dirsearch, nuclei, gospider, urls, etc.
		urlToParse = outputItem
	}

	if urlToParse == "" {
		return ""
	}

	// Now parse the URL and check if host is NOT an IP (i.e., is a domain)
	if !strings.HasPrefix(urlToParse, "http://") && !strings.HasPrefix(urlToParse, "https://") {
		urlToParse = "http://" + urlToParse
	}
	u, err := url.Parse(urlToParse)
	if err != nil {
		return ""
	}

	if !isIP(u.Hostname()) && u.Hostname() != "" {
		// For -d flag, return only host:port (without scheme)
		return u.Host // u.Host includes port if present
	}

	return ""
}

// getHost extracts the host/IP from a tool's output line.
// This is used by the -ip filter and the -d (extract domain) logic.
func getHost(outputItem string, toolType string) string {
	var host string
	if toolType == "nmap" {
		if strings.Contains(outputItem, " - ") {
			// Full format: [IP] - ...
			ipParts := strings.SplitN(outputItem, " - ", 2)
			if len(ipParts) > 0 {
				host = strings.Trim(ipParts[0], "[]")
			}
		} else {
			// IP:port format from -p flag
			host = getDomain(outputItem)
		}
	} else { // httpx, ffuf, dirsearch, nuclei, gospider, urls, amass
		host = getDomain(outputItem)
	}
	return host
}

// getIPHostWithPort extracts the host:port from a tool's output line if the host is an IP.
func getIPHostWithPort(outputItem string, toolType string) string {
	// For nmap, the output can be either "IP:port" or "[IP] - [port] - ..."
	if toolType == "nmap" {
		if strings.Contains(outputItem, " - ") { // Full format
			parts := strings.SplitN(outputItem, " - ", 3) // Split into IP, port, rest
			if len(parts) >= 2 {
				ip := strings.Trim(parts[0], "[]")
				port := strings.Trim(parts[1], "[]")
				if isIP(ip) {
					return ip + ":" + port
				}
			}
		} else { // Assumes IP:port format from -p flag
			host, _, err := net.SplitHostPort(outputItem)
			if err == nil && isIP(host) {
				return outputItem
			}
		}
		return "" // If nmap output couldn't be parsed for IP:port
	}

	// For all other tools, output item is the URL
	urlToParse := outputItem

	// Now parse the URL and check if host is IP
	if !strings.HasPrefix(urlToParse, "http://") && !strings.HasPrefix(urlToParse, "https://") {
		urlToParse = "http://" + urlToParse
	}
	u, err := url.Parse(urlToParse)
	if err != nil {
		return ""
	}

	if isIP(u.Hostname()) {
		return u.Host // u.Host is "hostname:port"
	}

	return ""
}

// processHttpxLine is in httpx.go
// processFfufLine is in ffuf.go
// processDirsearchLine is in dirsearch.go
// processAmassLine is in amass.go
// processNmapLine is in nmap.go
// processDnsxLine is in dnsx.go
// processNucleiLine is in nuclei.go
// processGospiderLine is in gospider.go
// processUrlsLine is in urls.go
