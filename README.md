# Urlx (Extract URL & More) 😺🔗

`Urlx` is a Go-based command-line tool designed to extract and process information from the output of various security assessment and utility tools like `httpx`, `ffuf`, `dirsearch`, `amass`, `nmap`, `dns`, `wafw00f`, `mantra`, and to perform direct domain extraction.

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
    *   `nuclei` (extracts URLs from scan results)
*   `domain` tool: Extracts domain/IP directly from a list of input URLs.
*   Common processing options:
    *   Extract redirect URLs (`-r` for applicable tools like `httpx`, `ffuf`).
    *   Strip URL components (path, query params, fragments) (`-s`).
    *   Extract domain/subdomain hostnames with port (excludes IPs, strips scheme/path/query/fragment) (`-d`).
*   Extract only hostname/IP from final output (`-hn`). For `mantra`, this extracts the hostname from the URL part of the "secret - URL" pair.
    *   Filter for URLs with an IP host and extracts the IP address and port (e.g., `1.2.3.4:443`) (`-ip`).
*   `httpx` & `ffuf` specific filter options:
    *   Filter by status codes (`-fc`).
    *   Filter by content length (`-fcl`).
    *   Filter by content type (`-fct`).
    *   Match by status codes (`-mc`).
    *   Match by content length (`-mcl`).
    *   Match by content type (`-mct`).
*   `nmap` specific options:
    *   Export IP and port pairs (`-p`).
    *   Filter for open ports only (`-o`).
*   `dns` specific options (mutually exclusive):
    *   Extract IP addresses (A/AAAA), sorted and unique (`-a`).
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

1.  Clone the repository (assuming a future GitHub path like `github.com/yourusername/urlx`):
    ```bash
    git clone https://github.com/yourusername/urlx.git
    cd urlx
    ```
2.  Build the executable (ensure all `.go` files are included if you have multiple parser files, e.g., `main.go`, `nmap.go`, `dns.go`, `mantra_parser.go`, etc.):
    ```bash
    go build -o urlx *.go
    ```
    You can then move `urlx` to a directory in your `PATH`, e.g., `/usr/local/bin` or `~/go/bin`.

### Using `go install` (from a future GitHub repository)

```bash
go install github.com/aleister1102/urlx@latest
```

This will download the source, compile it, and place the `urlx` executable in your `$GOPATH/bin` or `$HOME/go/bin` directory. Make sure this directory is in your system's `PATH`.

## 🚀 Usage

```
Usage: ./urlx <tool_name> [options] [input_file]

Available Tools:
  domain         Extracts domain/IP from a list of URLs.
                 Example: cat urls.txt | ./urlx domain
  httpx          Processes httpx output. Expects URLs or lines containing URLs.
                 Example: httpx -l list.txt -silent | ./urlx httpx -s -d
  ffuf           Processes ffuf output. Parses URLs from successful results.
                 Example: ffuf -w wordlist.txt -u https://example.com/FUZZ | ./urlx ffuf -r
  dirsearch      Processes dirsearch output. Extracts found paths and combines with target.
                 Example: dirsearch -u https://example.com -e php --simple-report | ./urlx dirsearch
  amass          Processes amass intel/enum output. Extracts hostnames.
                 Example: amass enum -d example.com | ./urlx amass
  nmap           Processes nmap output (standard -oN or -oG). Extracts IP, port, service, version.
                 Example: nmap -sV example.com | ./urlx nmap -o -p
  dns            Processes structured DNS record output (comma-separated). See specific options.
                 Example: cat dns_records.csv | ./urlx dns -a
  wafw00f        Processes wafw00f output. Extracts URL and detected WAF.
                 Example: wafw00f -i list_of_urls.txt | ./urlx wafw00f -k known
  mantra         Processes mantra output. Extracts secret and URL from found leaks.
                 Example: mantra -u https://example.com | ./urlx mantra
  nuclei         Processes nuclei output. Extracts URLs from scan results.
                 Example: nuclei -l targets.txt | ./urlx nuclei

Common Options (generally not applicable to 'domain' tool directly):
  -r             Extract redirect URLs (if tool output provides redirect info, e.g., httpx, ffuf).
  -s             Strip URL components (path, query parameters and fragments) before further processing or output.
  -d             Extract domain/subdomain hostnames with port (excludes IPs, strips scheme/path/query/fragment).
  -hn            Extract only hostname/IP from the final processed output. (Note: 'domain' tool inherently does this).
  -ip            Filters for URLs with an IP host and extracts the IP address and port (e.g., 1.2.3.4:443).
  -t <threads>   Number of concurrent processing threads (default: 1).

Nmap Specific Options ('nmap' tool only):
  -p             Export IP and port pairs (e.g., 192.168.1.1:80). Overrides default nmap format.
  -o             Filter for open ports only. Applied before -p if both are used.

Dns Specific Options ('dns' tool only - must choose one):
  -a             Extract IP addresses (A/AAAA records), sorted and unique.
  -cname         Extract CNAME domain records (the canonical name).
  -mx            Extract MX domain records (the mail exchange hostname).

Wafw00f Specific Options ('wafw00f' tool only):
  -k <kind>      WAF kind to extract: 'none', 'generic', or 'known' (default: 'none').

Filtering & Matching Options ('ffuf', 'httpx' tools):
  -f             Process all files in the current directory as ffuf input (ffuf only).
  -fc <codes>    Filter out responses with these status codes (e.g., 403,404).
  -fcl <lengths> Filter out responses with these content lengths (e.g., 0,123).
  -fct <types>   Filter out responses with these content types (e.g., text/html).
  -mc <codes>    Match responses with these status codes (e.g., 200,302).
  -mcl <lengths> Match responses with these content lengths (e.g., 512,1024).
  -mct <types>   Match responses with these content types (e.g., application/json).
  -pc            Preserve original line content on match (instead of extracting URL) (ffuf, httpx only).

Input:
  [input_file]   Optional. File to read input from. If omitted or '-', reads from stdin.
```

### Examples

1.  **Process `httpx` output, strip components, extract hostnames, using 10 threads:**
    ```bash
    cat httpx_output.txt | ./urlx httpx -s -hn -t 10
    ```

2.  **Process `httpx` output, matching only for 200 status codes:**
    ```bash
    cat httpx_output.txt | ./urlx httpx -mc 200
    ```

3.  **Process `ffuf` output, matching 200 codes and filtering out `text/html` content type:**
    ```bash
    cat ffuf_output.csv | ./urlx ffuf -mc 200 -fct text/html
    ```

4.  **Process `nmap` output, filter for open ports, and extract IP:Port pairs:**
    ```bash
    nmap -sV target.com -oN nmap_output.txt
    cat nmap_output.txt | ./urlx nmap -o -p
    ```

5.  **Extract only IPv4/IPv6 addresses from `dns` tool output (comma-separated format):**
    ```bash
    # Assuming dns_output.csv has lines like: query.com,A,N/A,1.2.3.4,...
    cat dns_output.csv | ./urlx dns -a
    ```

6.  **Process `wafw00f` output to find sites with a 'known' WAF:**
    ```bash
    wafw00f -i list_of_urls.txt | ./urlx wafw00f -k known
    # Output: http://example.com - Cloudflare
    ```

7.  **Extract domains directly from a list of URLs using the `domain` tool:**
    ```bash
    echo "https://example.com/path?query=true" | ./urlx domain
    # Output: example.com
    ```

8.  **Process `mantra` output to extract secrets and URLs:**
    ```bash
    # Assuming mantra_output.txt contains lines like:
    # [1;32m[+] [37m https://example.com/api.js  [1;32m[ [37mAPI_KEY_XYZ123 [1;32m] [37m
    # [31m[-] [37m  [37mUnable to make a request for ...
    cat mantra_output.txt | ./urlx mantra
    # Expected output: API_KEY_XYZ123 - https://example.com/api.js
    ```

9.  **Process `mantra` output and extract only the hostname from the identified URLs:**
    ```bash
    cat mantra_output.txt | ./urlx mantra -hn
    # Expected output: example.com
    ```

10. **Process `httpx` output and extract only domain/subdomain hostnames (excludes IP addresses):**
    ```bash
    cat httpx_output.txt | ./urlx httpx -d
    # Expected output: domain:port like example.com:8080 but not 192.168.1.1:8080
    # Note: -d flag strips scheme, path, query parameters, and fragments
    ```

11. **Process `nuclei` output to extract URLs from scan results:**
    ```bash
    nuclei -l targets.txt | ./urlx nuclei
    # Expected output: URLs found by nuclei scans
    ```

12. **Process `nuclei` output and extract only IP addresses and their ports from URLs:**
    ```bash
    nuclei -l targets.txt | ./urlx nuclei -ip
    # Expected output: A list of unique IP:port pairs (e.g., 91.184.63.175:3000) from the URLs
    ```

## 📝 Notes

*   The tool expects specific output formats for each supported tool. Refer to the respective tool's documentation.
*   When using `ffuf`, ensure you are using a format that outputs full URLs for successful hits.
*   The `dns` tool expects comma-separated values where the record type is the second field and the target value is the fourth field.
*   The `wafw00f` parser extracts the first URL and the WAF name from the end of the line (after the last closing parenthesis).
*   The `mantra` parser removes ANSI color codes, processes lines starting with `[+] `, and expects the format `URL  [SECRET]` to extract `SECRET - URL`.
*   Replace `yourusername/urlx` with the actual GitHub repository path when using `go install`.

---

Happy URL extracting! 🎉

## 🔮 Future Features
- Allow to filter by status code, content length, content type, etc. for more tools.
- Support for:
  - [x] amass
  - [x] nmap (filter open ports, extract IPv6, IP:port pairs, etc)
  - [x] ffuf (process folder, filter by code, content-type, length)
  - [x] httpx (filter by code, content-type, length)

## 🐛 Bugs
- Option `-mx` of `dns` subcommand is not working.
