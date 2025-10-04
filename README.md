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
| `dirsearch` | Process dirsearch output |
| `dnsx` | Process dnsx output (DNS records) |
| `ffuf` | Process ffuf output |
| `gospider` | Process gospider output |
| `httpx` | Process httpx output |
| `nmap` | Process nmap output |
| `nuclei` | Process nuclei output |
| `urls` | Process URL lists |

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

**dnsx:**
- `-a` Extract A records (IPv4 addresses)
- `-aaaa` Extract AAAA records (IPv6 addresses)
- `-cname` Extract CNAME records (canonical names)
- `-mx` Extract MX records (mail exchange hostnames)
- `-txt` Extract TXT records
- `-ns` Extract NS and SOA records (nameservers)

**ffuf/httpx/dirsearch:**
- `-fc <codes>` Filter out status codes
- `-fcl <lengths>` Filter out content lengths
- `-fct <types>` Filter out content types (ffuf, httpx only)
- `-mc <codes>` Match status codes
- `-mcl <lengths>` Match content lengths
- `-mct <types>` Match content types (ffuf, httpx only)
- `-pc` Preserve original content

## Examples

```bash
# Process httpx with filters
httpx -l targets.txt | urlx httpx -mc 200 -s

# Process ffuf output
ffuf -w wordlist.txt -u https://example.com/FUZZ | urlx ffuf -r

# Process dirsearch output with filters
dirsearch -u https://example.com -o output.txt
cat output.txt | urlx dirsearch -mc 200,301

# Extract redirect URLs from dirsearch
cat dirsearch.txt | urlx dirsearch -r -mc 301,302

# Filter out specific status codes
cat dirsearch.txt | urlx dirsearch -fc 404,403

# Extract IP:port from nmap
nmap -sV target.com | urlx nmap -o -p

# Process dnsx output to extract A records
dnsx -l subdomains.txt -a -resp | urlx dnsx -a

# Extract AAAA records (IPv6)
dnsx -l subdomains.txt -aaaa -resp | urlx dnsx -aaaa

# Extract MX records
dnsx -l domains.txt -mx -resp | urlx dnsx -mx

# Extract multiple record types
dnsx -l domains.txt -a -aaaa -cname -resp | urlx dnsx -a -aaaa -cname

# Extract TXT records
dnsx -l domains.txt -txt -resp | urlx dnsx -txt

# Extract nameservers
dnsx -l domains.txt -ns -resp | urlx dnsx -ns

# Process with multiple threads
dnsx -l domains.txt -a -resp | urlx dnsx -a -t 10
```

## Input

Reads from stdin or file. Use `-` for explicit stdin.