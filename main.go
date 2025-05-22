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
	fmt.Fprintf(os.Stderr, "Usage: %s <tool_name> [options] [input_file]\\n", os.Args[0])
	// fmt.Fprintln(os.Stderr, "  domain         : Optional subcommand. If used, equivalent to using the -d flag (extracts domain/IP only).") // Removed
	fmt.Fprintln(os.Stderr, "  <tool_name>    : Specify the tool (httpx, ffuf, dirsearch, amass, nmap, dns, wafw00f, domain). Mandatory.")
	fmt.Fprintln(os.Stderr, "  Tool Specific Information:")
	fmt.Fprintln(os.Stderr, "    domain         : Extracts domain/IP from a list of URLs.")
	fmt.Fprintln(os.Stderr, "  Common Options (not applicable to 'domain' tool directly, but affects other tools if used with them via -d):")
	fmt.Fprintln(os.Stderr, "    -r             : Extract redirect URLs.")
	fmt.Fprintln(os.Stderr, "    -s             : Strip URL components.")
	fmt.Fprintln(os.Stderr, "    -d             : Extract only domain/IP. (Note: 'domain' tool inherently does this).")
	fmt.Fprintln(os.Stderr, "    -t <threads>   : Number of concurrent threads (default: 1).")
	fmt.Fprintln(os.Stderr, "  Nmap Specific Options (if <tool_name> is 'nmap'):")
	fmt.Fprintln(os.Stderr, "    -p             : Export IP and port pairs.")
	fmt.Fprintln(os.Stderr, "    -o             : Filter for open ports only.")
	fmt.Fprintln(os.Stderr, "  Dns Specific Options (if <tool_name> is 'dns'):")
	fmt.Fprintln(os.Stderr, "    -ip            : Extract IP addresses (v4 & v6), sorted and unique.")
	fmt.Fprintln(os.Stderr, "    -cname         : Extract CNAME domain records.")
	fmt.Fprintln(os.Stderr, "    -mx            : Extract MX domain records (must be one of -ip, -cname, -mx).")
	fmt.Fprintln(os.Stderr, "  Wafw00f Specific Options (if <tool_name> is 'wafw00f'):")
	fmt.Fprintln(os.Stderr, "    -k <kind>      : WAF kind to extract (none, generic, known; default: none).")
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
	case "httpx", "ffuf", "dirsearch", "amass", "nmap", "dns", "wafw00f", "domain":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch, amass, nmap, dns, wafw00f, domain.\\n", toolType)
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
