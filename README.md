# UwU (Extract URL & More) 😺🔗

`UwU` is a Go-based command-line tool designed to extract and process information from the output of various security assessment and utility tools like `httpx`, `ffuf`, `dirsearch`, `amass`, `nmap`, `dns`, `wafw00f`, `mantra`, and to perform direct domain extraction.

## ✨ Features

*   Parses output from:
    *   `httpx` (URLs or lines containing URLs)
    *   `ffuf` (URLs from successful results)
    *   `dirsearch` (found paths combined with target)
    *   `amass` (hostnames from intel/enum output)
    *   `nmap` (standard -oN or -oG, extracts IP, port, service, version, IPv6 aware)
    *   `dns` (structured comma-separated DNS records)
    *   `wafw00f` (URL and detected WAF)
    *   `mantra` (extracts secrets and associated URLs from lines indicating found leaks)
*   `domain` tool: Extracts domain/IP directly from a list of input URLs.
*   Common processing options:
    *   Extract redirect URLs (`-r` for applicable tools like `httpx`, `ffuf`).
    *   Strip URL components (query params, fragments) (`-s`).
    *   Extract only domain/IP from final output (`-d`). For `mantra`, this extracts the domain from the URL part of the "secret - URL" pair.
*   `nmap` specific options:
    *   Export IP and port pairs (`-p`).
    *   Filter for open ports only (`-o`).
*   `dns` specific options (mutually exclusive):
    *   Extract IP addresses (A/AAAA), sorted and unique (`-ip`).
    *   Extract CNAME records (`-cname`).
    *   Extract MX domain records (mail exchange hostnames) (`-mx`).
*   `wafw00f` specific options:
    *   Filter by WAF kind (`-k <kind>`, where kind is `none`, `generic`, or `known`; default `none`).
    *   Outputs only URL if WAF is 'None' and `-k none` is used.
*   `mantra` processing:
    *   Ignores lines indicating errors or no findings (e.g., those starting with `[-]`).
    *   Parses lines indicating found secrets (e.g., `[+] http://example.com/script.js  [some_api_key]`).
    *   Outputs in the format: `some_api_key - http://example.com/script.js`.
*   Concurrent processing of input lines (`-t` flag for threads).
*   Reads from a file or standard input.

## 🛠️ Installation

### Prerequisites

*   Go (version 1.18 or later recommended).

### From Source

1.  Clone the repository (assuming a future GitHub path like `github.com/yourusername/uwu`):
    ```bash
    git clone https://github.com/yourusername/uwu.git
    cd uwu
    ```
2.  Build the executable (ensure all `.go` files are included if you have multiple parser files, e.g., `main.go`, `nmap.go`, `dns.go`, `mantra_parser.go`, etc.):
    ```bash
    go build -o uwu *.go
    ```
    You can then move `uwu` to a directory in your `PATH`, e.g., `/usr/local/bin` or `~/go/bin`.

### Using `go install` (from a future GitHub repository)

Once the project is available on GitHub (e.g., `github.com/yourusername/uwu`), you can install it directly:

```bash
go install github.com/yourusername/uwu@latest
```

This will download the source, compile it, and place the `uwu` executable in your `$GOPATH/bin` or `$HOME/go/bin` directory. Make sure this directory is in your system's `PATH`.

## 🚀 Usage

```
Usage: ./uwu <tool_name> [options] [input_file]

Available Tools:
  domain         Extracts domain/IP from a list of URLs.
                 Example: cat urls.txt | ./uwu domain
  httpx          Processes httpx output. Expects URLs or lines containing URLs.
                 Example: httpx -l list.txt -silent | ./uwu httpx -s -d
  ffuf           Processes ffuf output. Parses URLs from successful results.
                 Example: ffuf -w wordlist.txt -u https://example.com/FUZZ | ./uwu ffuf -r
  dirsearch      Processes dirsearch output. Extracts found paths and combines with target.
                 Example: dirsearch -u https://example.com -e php --simple-report | ./uwu dirsearch
  amass          Processes amass intel/enum output. Extracts hostnames.
                 Example: amass enum -d example.com | ./uwu amass
  nmap           Processes nmap output (standard -oN or -oG). Extracts IP, port, service, version.
                 Example: nmap -sV example.com | ./uwu nmap -o -p
  dns            Processes structured DNS record output (comma-separated). See specific options.
                 Example: cat dns_records.csv | ./uwu dns -ip
  wafw00f        Processes wafw00f output. Extracts URL and detected WAF.
                 Example: wafw00f -i list_of_urls.txt | ./uwu wafw00f -k known
  mantra         Processes mantra output. Extracts secret and URL from found leaks.
                 Example: mantra -u https://example.com | ./uwu mantra

Common Options (generally not applicable to 'domain' tool directly):
  -r             Extract redirect URLs (if tool output provides redirect info, e.g., httpx, ffuf).
  -s             Strip URL components (query parameters and fragments) before further processing or output.
  -d             Extract only domain/IP from the final processed output. (Note: 'domain' tool inherently does this).
  -t <threads>   Number of concurrent processing threads (default: 1).

Nmap Specific Options ('nmap' tool only):
  -p             Export IP and port pairs (e.g., 192.168.1.1:80). Overrides default nmap format.
  -o             Filter for open ports only. Applied before -p if both are used.

Dns Specific Options ('dns' tool only - must choose one):
  -ip            Extract IP addresses (A/AAAA records), sorted and unique.
  -cname         Extract CNAME domain records (the canonical name).
  -mx            Extract MX domain records (the mail exchange hostname).

Wafw00f Specific Options ('wafw00f' tool only):
  -k <kind>      WAF kind to extract: 'none', 'generic', or 'known' (default: 'none').

Input:
  [input_file]   Optional. File to read input from. If omitted or '-', reads from stdin.
```

### Examples

1.  **Process `httpx` output, strip components, extract domains, using 10 threads:**
    ```bash
    cat httpx_output.txt | ./uwu httpx -s -d -t 10
    ```

2.  **Process `nmap` output, filter for open ports, and extract IP:Port pairs:**
    ```bash
    nmap -sV target.com -oN nmap_output.txt
    cat nmap_output.txt | ./uwu nmap -o -p
    ```

3.  **Extract only IPv4/IPv6 addresses from `dns` tool output (comma-separated format):**
    ```bash
    # Assuming dns_output.csv has lines like: query.com,A,N/A,1.2.3.4,...
    cat dns_output.csv | ./uwu dns -ip
    ```

4.  **Process `wafw00f` output to find sites with a 'known' WAF:**
    ```bash
    wafw00f -i list_of_urls.txt | ./uwu wafw00f -k known
    # Output: http://example.com - Cloudflare
    ```

5.  **Extract domains directly from a list of URLs using the `domain` tool:**
    ```bash
    echo "https://example.com/path?query=true" | ./uwu domain
    # Output: example.com
    ```

6.  **Process `mantra` output to extract secrets and URLs:**
    ```bash
    # Assuming mantra_output.txt contains lines like:
    # [1;32m[+] [37m https://example.com/api.js  [1;32m[ [37mAPI_KEY_XYZ123 [1;32m] [37m
    # [31m[-] [37m  [37mUnable to make a request for ...
    cat mantra_output.txt | ./uwu mantra
    # Expected output: API_KEY_XYZ123 - https://example.com/api.js
    ```

7.  **Process `mantra` output and extract only the domain from the identified URLs:**
    ```bash
    cat mantra_output.txt | ./uwu mantra -d
    # Expected output: example.com
    ```

## 📝 Notes

*   The tool expects specific output formats for each supported tool. Refer to the respective tool's documentation.
*   When using `ffuf`, ensure you are using a format that outputs full URLs for successful hits.
*   The `dns` tool expects comma-separated values where the record type is the second field and the target value is the fourth field.
*   The `wafw00f` parser extracts the first URL and the WAF name from the end of the line (after the last parenthesis).
*   The `mantra` parser removes ANSI color codes, processes lines starting with `[+] `, and expects the format `URL  [SECRET]` to extract `SECRET - URL`.
*   Replace `yourusername/uwu` with the actual GitHub repository path when using `go install`.

---

Happy URL extracting! 🎉

## 🔮 Future Features
- Allow to filter by status code, content length, content type, etc.
- Support for:
  - [x] amass
  - [x] nmap (filter open ports, extract IPv6, IP:port pairs, etc)
  - [ ] ffuf for a directory (process all files in the current directory), filter by code, content-type, length, etc.

## 🐛 Bugs
- Option `-mx` of `dns` subcommand is not working.