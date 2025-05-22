#  UwU 😺🔗

`UwU` is a Go-based command-line tool designed to extract URLs from the output of various security assessment tools like `httpx`, `ffuf`, and `dirsearch`. It helps streamline the process of gathering and cleaning up URLs for further analysis.

## ✨ Features

*   Parses output from `httpx`, `ffuf` (CSV format), and `dirsearch`.
*   Optional extraction of redirect URLs (`-r`).
*   Optional stripping of URL query parameters and fragments (`-s`).
*   Optional extraction of only the domain name from URLs (`-d`).
*   Concurrent processing of input lines for faster results (`-p` or `-c` flags).
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

This will download the source, compile it, and place the `uwu` (or `extracturl` if you rename the output binary in the go.mod or build process) executable in your `$GOPATH/bin` or `$HOME/go/bin` directory. Make sure this directory is in your system's `PATH`.

## 🚀 Usage

```
Usage: ./extracturl -t <tool_name> [-r] [-s] [-d] [-p <threads>] [-c <threads>] [input_file]

Options:
  -t <tool_name> : Specify the tool (httpx, ffuf, dirsearch). Mandatory.
  -r             : Extract redirect URLs (if available and tool supports it).
  -s             : Strip URL components (query params, fragments).
  -d             : Extract only the domain from URLs.
  -p <threads>   : Number of parallel threads (default: 1).
  -c <threads>   : Number of concurrent threads (alias for -p, default: 1).
  input_file     : Optional input file. If not provided, reads from stdin.
```

### Examples

1.  **Process `httpx` output from a file, strip components, using 10 threads:**
    ```bash
    cat httpx_output.txt | ./extracturl -t httpx -s -c 10
    ```
    Alternatively:
    ```bash
    ./extracturl -t httpx -s -c 10 httpx_output.txt
    ```

2.  **Process `ffuf` output from stdin and extract redirect URLs:**
    ```bash
    ffuf -u https://example.com/FUZZ -w wordlist.txt -oc ffuf_results.csv -of csv
    cat ffuf_results.csv | ./extracturl -t ffuf -r
    ```

3.  **Process `dirsearch` output, strip components and extract redirects:**
    ```bash
    dirsearch -u https://target.com -e php,html --output=dirsearch_log.txt
    cat dirsearch_log.txt | ./extracturl -t dirsearch -s -r
    ```

4.  **Process `httpx` output and extract only domains:**
    ```bash
    cat httpx_output.txt | ./extracturl -t httpx -d
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
