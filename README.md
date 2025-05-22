#  UwU (Extract URL) 😺🔗

`UwU` is a Go-based command-line tool designed to extract URLs and other information from the output of various security assessment tools like `httpx`, `ffuf`, `dirsearch`, `amass`, and `nmap`. It helps streamline the process of gathering and cleaning up data for further analysis.

## ✨ Features

*   Parses output from `httpx`, `ffuf` (CSV format), `dirsearch`, `amass` (standard and MX record format), and `nmap` (standard scan output).
*   Optional extraction of redirect URLs (`-r` for URL-based tools).
*   Optional stripping of URL query parameters and fragments (`-s` for URL-based tools).
*   Optional extraction of only the domain name (for URL-based tools) or IP address (for `nmap`) using the (`-d`) flag.
*   Concurrent processing of input lines for faster results (`-t` flag for threads).
*   Reads from a file or standard input.

## 🛠️ Installation

### Prerequisites

*   Go (version 1.18 or later recommended).

### From Source

1.  Clone the repository (assuming you will host this on GitHub at `github.com/aleister1102/uwu`):
    ```bash
    git clone https://github.com/aleister1102/uwu.git
    cd uwu
    ```
2.  Build the executable:
    ```bash
    go build -o extracturl main.go
    ```
    You can then move `extracturl` to a directory in your `PATH`, e.g., `/usr/local/bin` or `~/go/bin`.

### Using `go install` (from GitHub)

Once the project is available on GitHub (e.g., `github.com/aleister1102/uwu`), you can install it directly:

```bash
go install github.com/aleister1102/uwu@latest
```

This will download the source, compile it, and place the `uwu` executable in your `$GOPATH/bin` or `$HOME/go/bin` directory. Make sure this directory is in your system's `PATH`.

## 🚀 Usage

```
Usage: ./uwu <tool_name> [-r] [-s] [-d] [-t <threads>] [input_file]

Subcommands (Tool Name):
  httpx          Process httpx output.
  ffuf           Process ffuf CSV output.
  dirsearch      Process dirsearch output.
  amass          Process amass output (standard or MX record).
  nmap           Process nmap standard scan output.

Options:
  -r             : Extract redirect URLs (if available and tool supports it, e.g., for httpx, dirsearch, ffuf).
  -s             : Strip URL components (query params, fragments; e.g., for httpx, dirsearch, ffuf).
  -d             : Extract only the domain (for URL-based tools like httpx, ffuf, dirsearch, amass) or IP address (for nmap).
  -t <threads>   : Number of concurrent threads (default: 1).
  input_file     : Optional input file. If not provided, reads from stdin.
```

### Examples

1.  **Process `httpx` output from a file, strip components, using 10 threads:**
    ```bash
    cat httpx_output.txt | ./uwu httpx -s -t 10
    ```
    Alternatively:
    ```bash
    ./uwu httpx -s -t 10 httpx_output.txt
    ```

2.  **Process `ffuf` output from stdin and extract redirect URLs:**
    ```bash
    ffuf -u https://example.com/FUZZ -w wordlist.txt -oc ffuf_results.csv -of csv
    cat ffuf_results.csv | ./uwu ffuf -r
    ```

3.  **Process `dirsearch` output, strip components and extract redirects:**
    ```bash
    dirsearch -u https://target.com -e php,html --output=dirsearch_log.txt
    cat dirsearch_log.txt | ./uwu dirsearch -s -r
    ```

4.  **Process `httpx` output and extract only domains:**
    ```bash
    cat httpx_output.txt | ./uwu httpx -d
    ```

5.  **Process `amass` standard output and extract only domains (using 5 threads):**
    ```bash
    amass enum -d example.com -o amass_output.txt
    cat amass_output.txt | ./uwu amass -d -t 5
    ```

6.  **Process `amass` active MX record output:**
    ```bash
    amass enum -d example.com -active -o amass_active_output.txt
    cat amass_active_output.txt | ./uwu amass 
    # This will output both the source and target FQDNs from MX records on separate lines.
    ```

7.  **Process `amass` active MX record output and extract only domains:**
    ```bash
    cat amass_active_output.txt | ./uwu amass -d
    # This will attempt to extract the domain from each FQDN found in MX records.
    ```

8.  **Process `nmap` output to extract IP, port, service, version, and status (using 20 threads):**
    ```bash
    nmap -sV target.com -oN nmap_output.txt
    cat nmap_output.txt | ./uwu nmap -t 20
    # Output format: [IP_ADDRESS] - [PORT] - [SERVICE_NAME] - [VERSION] - [STATUS]
    ```

9.  **Process `nmap` output and extract only IP addresses:**
    ```bash
    cat nmap_output.txt | ./uwu nmap -d
    ```

## 📝 Notes

*   The tool expects specific output formats for each supported tool. Refer to the respective tool's documentation for their standard output formats.
*   When using `ffuf`, ensure you are using the CSV output format (`-of csv`).
*   Replace `aleister1102/uwu` with the actual GitHub repository path when using `go install`.

--- 

Happy URL extracting! 🎉 

## 🔮 Future Features
- Allow to filter by status code, content length, content type, etc.
- Support for:
  - amass
  - nmap (filter open ports, extract IPv6, IP:port pairs, etc)

## 🐛 Bugs
- Option `-mx` of `dns` subcommand is not working.