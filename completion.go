package main

import (
	"fmt"
	"os"
)

const bashCompletionScript = `
_urlx_complete()
{
    local cur prev words
    _get_comp_words_by_ref -n : cur prev words

    # Complete subcommands
    if [ "$prev" == "urlx" ]; then
        COMPREPLY=( $(compgen -W "domain httpx ffuf dirsearch amass nmap dns wafw00f mantra nuclei gospider completion" -- "$cur") )
        return
    fi

    # Complete for completion subcommand
    if [ "$prev" == "completion" ]; then
        COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
        return
    fi
    
    # Find the subcommand in the command line
    local tool
    for word in "${words[@]}"; do
        case "$word" in
            domain|httpx|ffuf|dirsearch|amass|nmap|dns|wafw00f|mantra|nuclei|gospider)
                tool="$word"
                break
                ;;
        esac
    done

    # Complete flags
    if [[ "$cur" == -* ]]; then
        local flags_common="-r -s -d -hn -ip -t"
        local flags_tool=""
        case "$tool" in
            nmap)
                flags_tool="-p -o"
                ;;
            dns)
                flags_tool="-a -cname -mx"
                ;;
            wafw00f)
                flags_tool="-k"
                ;;
            httpx|ffuf)
                flags_tool="-fc -fcl -fct -mc -mcl -mct -pc"
                if [[ "$tool" == "ffuf" ]]; then
                    flags_tool="$flags_tool -f"
                fi
                ;;
        esac
        COMPREPLY=( $(compgen -W "${flags_common} ${flags_tool}" -- "$cur") )
        return
    fi

    # Complete arguments for flags
    case "$prev" in
        -k)
            COMPREPLY=( $(compgen -W "none generic known" -- "$cur") )
            return
            ;;
    esac
}

complete -F _urlx_complete urlx
`

const zshCompletionScript = `
#compdef urlx

_urlx() {
    local -a common_flags tool_flags subcommands
    
    subcommands=(
        'domain:Extracts domain/IP from a list of URLs'
        'httpx:Processes httpx output'
        'ffuf:Processes ffuf output'
        'dirsearch:Processes dirsearch output'
        'amass:Processes amass intel/enum output'
        'nmap:Processes nmap output'
        'dns:Processes structured DNS record output'
        'wafw00f:Processes wafw00f output'
        'mantra:Processes mantra output'
        'nuclei:Processes nuclei output'
        'gospider:Processes gospider output'
        'completion:Generate completion script for bash/zsh'
    )

    common_flags=(
        '-r:Extract redirect URLs'
        '-s:Strip URL components'
        '-d:Extract domain/subdomain hostnames with port'
        '-hn:Extract only hostname/IP from final output'
        '-ip:Filter for URLs with an IP host and extract IP:port'
        '*-t:Number of concurrent processing threads'
    )
    
    local ret=1
    
    # Find the tool command
    local tool_cmd
    for word in ${words[@]}; do
        case $word in
            (domain|httpx|ffuf|dirsearch|amass|nmap|dns|wafw00f|mantra|nuclei|gospider)
                tool_cmd=$word
                break
            ;;
        esac
    done

    case $tool_cmd in
        nmap)
            tool_flags=(
                '-p:Export IP and port pairs'
                '-o:Filter for open ports only'
            )
            ;;
        dns)
            tool_flags=(
                '-a:Extract IP addresses (A/AAAA records)'
                '-cname:Extract CNAME domain records'
                '-mx:Extract MX domain records'
            )
            ;;
        wafw00f)
            tool_flags=(
                '(-k)-k[WAF kind to extract]:WAF Kind:(none generic known)'
            )
            ;;
        httpx|ffuf)
            tool_flags=(
                '*-fc:Filter out responses with these status codes'
                '*-fcl:Filter out responses with these content lengths'
                '*-fct:Filter out responses with these content types'
                '*-mc:Match responses with these status codes'
                '*-mcl:Match responses with these content lengths'
                '*-mct:Match responses with these content types'
                '-pc:Preserve original line content on match'
            )
            if [[ "$tool_cmd" == "ffuf" ]]; then
                tool_flags+=('-f:Process all files in the current directory')
            fi
            ;;
        completion)
            _arguments "2: :((bash\:Bash completion script),(zsh\:Zsh completion script))"
            return
            ;;
    esac

    if (( CURRENT == 2 )); then
        _describe -t commands 'urlx command' subcommands && ret=0
    elif (( CURRENT > 2 )); then
        _arguments -s -S $common_flags $tool_flags '*:filename:_files' && ret=0
    fi
    
    return ret
}

_urlx "$@"
`

func handleCompletion(shell string) {
	switch shell {
	case "bash":
		fmt.Print(bashCompletionScript)
	case "zsh":
		fmt.Print(zshCompletionScript)
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported shell '%s'. Please use 'bash' or 'zsh'.\n", shell)
		os.Exit(1)
	}
}
