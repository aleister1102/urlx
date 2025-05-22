package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	extractRedirect   bool
	stripComponents   bool
	extractDomainOnly bool // Flag -d, áp dụng cho các tool khác domain
	numThreads        int
	// Nmap specific flags
	nmapExportIPPort    bool
	nmapFilterOpenPorts bool
	// Dns specific flags
	dnsExtractIP    bool
	dnsExtractCNAME bool
	dnsExtractMX    bool
	// Wafw00f specific flag
	wafKindFilter string
	// isDomainSubcommandUsed // No longer needed
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <tool_name> [options] [input_file]\\n\\n", os.Args[0])

	fmt.Fprintln(os.Stderr, "Available Tools:")
	fmt.Fprintln(os.Stderr, "  domain         Extracts domain/IP from a list of URLs.")
	fmt.Fprintln(os.Stderr, "                 Example: cat urls.txt | go_parser domain")
	fmt.Fprintln(os.Stderr, "  httpx          Processes httpx output. Expects URLs or lines containing URLs.")
	fmt.Fprintln(os.Stderr, "                 Example: httpx -l list.txt -silent | go_parser httpx -s -d")
	fmt.Fprintln(os.Stderr, "  ffuf           Processes ffuf output. Parses URLs from successful results.")
	fmt.Fprintln(os.Stderr, "                 Example: ffuf -w wordlist.txt -u https://example.com/FUZZ | go_parser ffuf -r")
	fmt.Fprintln(os.Stderr, "  dirsearch      Processes dirsearch output. Extracts found paths and combines with target.")
	fmt.Fprintln(os.Stderr, "                 Example: dirsearch -u https://example.com -e php --simple-report | go_parser dirsearch")
	fmt.Fprintln(os.Stderr, "  amass          Processes amass intel/enum output. Extracts hostnames.")
	fmt.Fprintln(os.Stderr, "                 Example: amass enum -d example.com | go_parser amass")
	fmt.Fprintln(os.Stderr, "  nmap           Processes nmap output (standard -oN or -oG). Extracts IP, port, service, version.")
	fmt.Fprintln(os.Stderr, "                 Example: nmap -sV example.com | go_parser nmap -o -p")
	fmt.Fprintln(os.Stderr, "  dns            Processes structured DNS record output (comma-separated). See specific options.")
	fmt.Fprintln(os.Stderr, "                 Example: cat dns_records.csv | go_parser dns -ip")
	fmt.Fprintln(os.Stderr, "  wafw00f        Processes wafw00f output. Extracts URL and detected WAF.")
	fmt.Fprintln(os.Stderr, "                 Example: wafw00f -i list_of_urls.txt | go_parser wafw00f -k known")
	fmt.Fprintln(os.Stderr, "  mantra         Processes mantra output. Extracts secret and URL from found leaks.")
	fmt.Fprintln(os.Stderr, "                 Example: mantra -u https://example.com | go_parser mantra\\n")

	fmt.Fprintln(os.Stderr, "Common Options (generally not applicable to 'domain' tool directly):")
	fmt.Fprintln(os.Stderr, "  -r             Extract redirect URLs (if tool output provides redirect info, e.g., httpx, ffuf).")
	fmt.Fprintln(os.Stderr, "  -s             Strip URL components (query parameters and fragments) before further processing or output.")
	fmt.Fprintln(os.Stderr, "  -d             Extract only domain/IP from the final processed output. (Note: 'domain' tool inherently does this).")
	fmt.Fprintln(os.Stderr, "  -t <threads>   Number of concurrent processing threads (default: 1).\\n")

	fmt.Fprintln(os.Stderr, "Nmap Specific Options ('nmap' tool only):")
	fmt.Fprintln(os.Stderr, "  -p             Export IP and port pairs (e.g., 192.168.1.1:80). Overrides default nmap format.")
	fmt.Fprintln(os.Stderr, "  -o             Filter for open ports only. Applied before -p if both are used.\\n")

	fmt.Fprintln(os.Stderr, "Dns Specific Options ('dns' tool only - must choose one):")
	fmt.Fprintln(os.Stderr, "  -ip            Extract IP addresses (A/AAAA records), sorted and unique.")
	fmt.Fprintln(os.Stderr, "  -cname         Extract CNAME domain records (the canonical name).")
	fmt.Fprintln(os.Stderr, "  -mx            Extract MX domain records (the mail exchange hostname).\\n")

	fmt.Fprintln(os.Stderr, "Wafw00f Specific Options ('wafw00f' tool only):")
	fmt.Fprintln(os.Stderr, "  -k <kind>      WAF kind to extract: 'none', 'generic', or 'known' (default: 'none').\\n")

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

	// Define common flags. Note: -d is defined here but its primary effect is for tools other than 'domain'.
	cmdFlags.BoolVar(&extractRedirect, "r", false, "Extract redirect URLs")
	cmdFlags.BoolVar(&stripComponents, "s", false, "Strip URL components")
	cmdFlags.BoolVar(&extractDomainOnly, "d", false, "Extract only domain/IP from URLs/output (for relevant tools)")
	cmdFlags.IntVar(&numThreads, "t", 1, "Number of concurrent threads")

	// Tool-specific flags
	cmdFlags.BoolVar(&nmapExportIPPort, "p", false, "Export IP and port pairs (nmap only)")
	cmdFlags.BoolVar(&nmapFilterOpenPorts, "o", false, "Filter for open ports only (nmap only)")

	cmdFlags.BoolVar(&dnsExtractIP, "ip", false, "Extract IP addresses (dns only)")
	cmdFlags.BoolVar(&dnsExtractCNAME, "cname", false, "Extract CNAME records (dns only)")
	cmdFlags.BoolVar(&dnsExtractMX, "mx", false, "Extract MX records (dns only)")

	cmdFlags.StringVar(&wafKindFilter, "k", "none", "WAF kind to extract (none, generic, known) (wafw00f only)")

	err := cmdFlags.Parse(argsForFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\\n", err)
		usage()
	}

	// No longer need to set extractDomainOnly based on isDomainSubcommandUsed

	switch toolType {
	case "httpx", "ffuf", "dirsearch", "amass", "nmap", "dns", "wafw00f", "domain", "mantra":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch, amass, nmap, dns, wafw00f, domain, mantra.\\n", toolType)
		usage()
	}

	if toolType == "dns" && !dnsExtractIP && !dnsExtractCNAME && !dnsExtractMX {
		fmt.Fprintln(os.Stderr, "Error: For 'dns' tool, you must specify one of -ip, -cname, or -mx options.")
		usage()
	}

	if toolType == "wafw00f" {
		if wafKindFilter != "none" && wafKindFilter != "generic" && wafKindFilter != "known" {
			fmt.Fprintf(os.Stderr, "Error: Invalid value for -k option: '%s'. Must be one of none, generic, or known.\\n", wafKindFilter)
			usage()
		}
	}

	// If the 'domain' tool is used, no other flags are expected or processed for it by this logic block.
	// It inherently extracts domains.

	if numThreads < 1 {
		fmt.Fprintln(os.Stderr, "Error: -t <threads> must be a positive integer.")
		usage()
	}

	var inputFile string
	remainingArgs := cmdFlags.Args()
	if len(remainingArgs) > 0 {
		inputFile = remainingArgs[0]
	} else {
		inputFile = ""
	}

	var reader *bufio.Reader
	var file *os.File
	var err2 error

	if inputFile != "" && inputFile != "-" {
		file, err2 = os.Open(inputFile)
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "Error: Cannot read file '%s': %v\\n", inputFile, err2)
			os.Exit(1)
		}
		defer file.Close()
		reader = bufio.NewReader(file)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode()&os.ModeCharDevice) == 0 || inputFile == "-" {
			reader = bufio.NewReader(os.Stdin)
		} else {
			fmt.Fprintln(os.Stderr, "Error: No input file provided and no data piped to stdin.")
			usage()
		}
	}
	if reader == nil {
		fmt.Fprintln(os.Stderr, "Error: Input reader was not initialized.")
		os.Exit(1)
	}

	linesChan := make(chan string, numThreads)
	resultsChan := make(chan string, numThreads)
	var wg sync.WaitGroup
	var outputWg sync.WaitGroup

	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			linesChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\\n", err)
		}
		close(linesChan)
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
					result := processHttpxLine(line)
					if result != "" {
						processedOutputs = append(processedOutputs, result)
					}
				case "ffuf":
					result := processFfufLine(line)
					if result != "" {
						processedOutputs = append(processedOutputs, result)
					}
				case "dirsearch":
					result := processDirsearchLine(line)
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
				case "dns":
					dnsResults := processDnsLine(line)
					processedOutputs = append(processedOutputs, dnsResults...)
				case "wafw00f":
					wafw00fResults := processWafw00fLine(line)
					processedOutputs = append(processedOutputs, wafw00fResults...)
				case "domain":
					domainResult := processDomainToolLine(line)
					if domainResult != "" {
						processedOutputs = append(processedOutputs, domainResult)
					}
				case "mantra":
					mantraResult := processMantraLine(line)
					if mantraResult != "" {
						processedOutputs = append(processedOutputs, mantraResult)
					}
				}
				for _, outputItem := range processedOutputs {
					if outputItem == "" {
						continue
					}
					// Nếu tool là 'domain', nó đã tự trích xuất domain rồi.
					// Đối với các tool khác, kiểm tra cờ extractDomainOnly.
					if toolType == "domain" {
						resultsChan <- outputItem // outputItem đã là domain/IP
					} else if extractDomainOnly {
						var domainOrIP string
						if toolType == "nmap" {
							ipParts := strings.SplitN(outputItem, " - ", 2)
							if len(ipParts) > 0 {
								domainOrIP = strings.Trim(ipParts[0], "[]")
							}
						} else if toolType == "wafw00f" {
							urlAndWaf := strings.SplitN(outputItem, " - ", 2)
							if len(urlAndWaf) > 0 {
								domainOrIP = getDomain(urlAndWaf[0])
							}
						} else if toolType == "mantra" {
							// Output is "secret - URL"
							secretAndURL := strings.SplitN(outputItem, " - ", 2)
							if len(secretAndURL) == 2 {
								domainOrIP = getDomain(secretAndURL[1]) // Get domain from URL part
							}
						} else {
							domainOrIP = getDomain(outputItem)
						}
						if domainOrIP != "" {
							resultsChan <- domainOrIP
						}
					} else {
						resultsChan <- outputItem
					}
				}
			}
		}()
	}

	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		if toolType == "dns" && dnsExtractIP {
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
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// processHttpxLine is in parser_httpx.go
// processFfufLine is in parser_ffuf.go
// processDirsearchLine is in parser_dirsearch.go
// processAmassLine is in parser_amass.go
// processNmapLine is in nmap.go
// processDnsLine is in dns.go
// processWafw00fLine is in wafw00f.go
// processDomainToolLine is in domain_parser.go
// processMantraLine is in mantra_parser.go
