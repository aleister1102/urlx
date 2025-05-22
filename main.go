package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"

	// "regexp" // No longer used directly in main.go
	"strings"
	"sync"
)

var (
	// toolType is now derived from subcommand
	extractRedirect   bool
	stripComponents   bool
	extractDomainOnly bool
	numThreads        int // Renamed from parallelThreads, set by new -t flag
	// inputFile is now a local variable in main
)

func usage() {
	// Note: The usage message needs to be manually maintained to reflect FlagSet usage
	fmt.Fprintf(os.Stderr, "Usage: %s <tool_name> [-r] [-s] [-d] [-t <threads>] [input_file]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  <tool_name>    : Specify the tool (httpx, ffuf, dirsearch, amass, nmap). Mandatory.")
	fmt.Fprintln(os.Stderr, "  -r             : Extract redirect URLs (if available and tool supports it).")
	fmt.Fprintln(os.Stderr, "  -s             : Strip URL components (query params, fragments).")
	fmt.Fprintln(os.Stderr, "  -d             : Extract only the domain/IP from URLs/output.")
	fmt.Fprintln(os.Stderr, "  -t <threads>   : Number of concurrent threads (default: 1).")
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
		fmt.Fprintln(os.Stderr, "Error: <tool_name> subcommand is mandatory.")
		usage()
	}

	toolType := os.Args[1]

	// Create a new FlagSet for arguments after the subcommand
	cmdFlags := flag.NewFlagSet(toolType, flag.ExitOnError)
	cmdFlags.Usage = usage // Point to our custom usage function

	// Define flags on this FlagSet, using global variables
	cmdFlags.BoolVar(&extractRedirect, "r", false, "Extract redirect URLs")
	cmdFlags.BoolVar(&stripComponents, "s", false, "Strip URL components (query params, fragments)")
	cmdFlags.BoolVar(&extractDomainOnly, "d", false, "Extract only the domain/IP from URLs/output")
	cmdFlags.IntVar(&numThreads, "t", 1, "Number of concurrent threads")

	// Parse the flags from os.Args[2:] (arguments after the subcommand)
	err := cmdFlags.Parse(os.Args[2:])
	if err != nil { // Handle parsing errors (though ExitOnError should handle it)
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		usage()
	}

	switch toolType {
	case "httpx", "ffuf", "dirsearch", "amass", "nmap":
		// Known tool
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported tool type '%s'. Supported tools are: httpx, ffuf, dirsearch, amass, nmap.\n", toolType)
		usage()
	}

	if numThreads < 1 {
		fmt.Fprintln(os.Stderr, "Error: -t <threads> must be a positive integer.")
		usage()
	}

	var inputFile string             // inputFile is now a local variable
	remainingArgs := cmdFlags.Args() // Get non-flag arguments after FlagSet parsing
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
			fmt.Fprintf(os.Stderr, "Error: Cannot read file '%s': %v\n", inputFile, err2)
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

	linesChan := make(chan string, numThreads)
	resultsChan := make(chan string, numThreads)
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
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var currentNmapIPContext string // Context for nmap IP, specific to each worker
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
						potentialHostnames := strings.Split(result, "\n")
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
				}
				for _, outputItem := range processedOutputs {
					if outputItem == "" { // Should already be handled by individual processors, but good check
						continue
					}
					if extractDomainOnly {
						var domainOrIP string
						if toolType == "nmap" {
							// Extract IP from the nmap formatted string: "[IP] - ..."
							ipParts := strings.SplitN(outputItem, " - ", 2) // Split at the first " - "
							if len(ipParts) > 0 {
								domainOrIP = strings.Trim(ipParts[0], "[]")
							}
						} else {
							domainOrIP = getDomain(outputItem) // Existing logic for other tools
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

// processHttpxLine is now in parser_httpx.go

// processFfufLine is now in parser_ffuf.go

// processDirsearchLine is now in parser_dirsearch.go

// processAmassLine is now in parser_amass.go

// processNmapLine is now in parser_nmap.go
