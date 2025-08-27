# urlx

Command-line tool for extracting and processing URLs from security tool outputs.

## Installation

```bash
go install github.com/aleister1102/urlx@latest
```

Or build from source:
```bash
git clone https://github.com/aleister1102/urlx.git
cd urlx
go build -o urlx .
```

## Usage

```
urlx <tool> [options] [input_file]
```

### Supported Tools

| Tool | Description |
|------|-------------|
| `amass` | Process amass output |
| `completion` | Generate shell completion |
| `dirsearch` | Process dirsearch output |
| `dns` | Process DNS records |
| `domain` | Extract domains/IPs from URLs |
| `ffuf` | Process ffuf output |
| `gospider` | Process gospider output |
| `httpx` | Process httpx output |
| `mantra` | Process mantra output |
| `nmap` | Process nmap output |
| `nuclei` | Process nuclei output |
| `urls` | Process URL lists |
| `wafw00f` | Process wafw00f output |

### Common Options

| Flag | Description |
|------|-------------|
| `-r` | Extract redirect URLs |
| `-s` | Strip URL components |
| `-d` | Extract domain/subdomain hostnames with port (excludes IPs) |
| `-ip` | Filter for IP hosts and extract IP:port |
| `-t <n>` | Number of threads (default: 1) |

### Tool-Specific Options

**nmap:**
- `-p` Export IP:port pairs
- `-o` Filter open ports only

**dns:**
- `-a` Extract A/AAAA records
- `-cname` Extract CNAME records  
- `-mx` Extract MX records

**wafw00f:**
- `-k <kind>` WAF filter: none/generic/known (default: none)

**ffuf/httpx:**
- `-fc <codes>` Filter out status codes
- `-fcl <lengths>` Filter out content lengths
- `-fct <types>` Filter out content types
- `-mc <codes>` Match status codes
- `-mcl <lengths>` Match content lengths
- `-mct <types>` Match content types
- `-pc` Preserve original content

## Examples

```bash
# Extract domains from URLs
echo "https://example.com/path" | urlx domain

# Process httpx with filters
httpx -l targets.txt | urlx httpx -mc 200 -s

# Process ffuf output
ffuf -w wordlist.txt -u https://example.com/FUZZ | urlx ffuf -r

# Extract IP:port from nmap
nmap -sV target.com | urlx nmap -o -p

# Process DNS records
cat dns.csv | urlx dns -a

# Generate completion
urlx completion bash > /etc/bash_completion.d/urlx
```

## Input

Reads from stdin or file. Use `-` for explicit stdin.

## Completion

Generate shell completion:
```bash
urlx completion bash  # or zsh
```