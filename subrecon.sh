#!/bin/bash
#
# subrecon.sh — Bug Bounty Reconnaissance Automation
#
# Stages:
#   1. Subdomain enumeration (assetfinder, subfinder, amass, crt.sh) + dnsx resolve
#   2. Live host discovery (httpx) + tech detection + status splitting
#   3. URL collection & crawling (katana, waybackurls, gau) + normalization (uro)
#
# Usage:
#   ./subrecon.sh target.com
#   ./subrecon.sh -v target.com                     # verbose: show full tool output
#   ./subrecon.sh target.com second.com third.com   # multiple domains, one output tree each
#   ./subrecon.sh -v target.com second.com           # flags can go before or mixed in
#
# Options:
#   -v, --verbose   Show full output/errors from every tool instead of just summaries
#   -h, --help      Show usage
#
# Requires (must be in $PATH):
#   assetfinder subfinder amass crt.sh(curl) dnsx httpx katana
#   waybackurls gau hakcheckurl anew uro
#
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/subrecon}"
VERBOSE=0
DOMAINS=()

usage() {
    cat << EOF
subrecon.sh — Bug Bounty Reconnaissance Automation

Runs subdomain enumeration, live host discovery, and URL collection/crawling
against one or more domains, saving results under a per-domain output tree.

USAGE:
    $0 [OPTIONS] domain1.com [domain2.com ...]

OPTIONS:
    -v, --verbose     Show full output/errors from every tool instead of
                       just step names and result counts
    -h, --help        Show this help menu and exit

ENVIRONMENT:
    BASE_DIR          Override the output base directory
                       (default: \$HOME/recon)

EXAMPLES:
    $0 target.com
    $0 -v target.com
    $0 target.com second.com third.com
    BASE_DIR=/data/recon $0 target.com

STAGES:
    1. Subdomain enumeration   assetfinder, subfinder, amass, crt.sh -> dnsx resolve
    2. Live host discovery     httpx (tech detect, status codes, 401/403 split)
    3. URL collection & crawl  katana, gau, waybackurls -> merge -> uro normalize

OUTPUT (per domain, under \$BASE_DIR/<domain>/):
    subs/       raw + resolved subdomains
    live/       httpx results, live hosts, 200s, auth-required hosts
    js/         katana crawl output
    params/     gau + waybackurls historical URLs
    findings/   priority subdomains (api./admin./staging./auth./etc.)
    all_urls.txt      merged, deduped, static-asset-filtered URLs
    clean_urls.txt    normalized dataset (feed into gf, nuclei, dalfox, sqlmap, etc.)

REQUIRES (must be in \$PATH):
    assetfinder subfinder amass curl dnsx httpx katana
    waybackurls gau hakcheckurl anew uro

NOTE:
    Only run this against targets you are authorized to test
    (an active bug bounty scope or written permission).
EOF
    exit 0
}

# ---- Argument parsing (flags can appear anywhere) ----
for arg in "$@"; do
    case "$arg" in
        -v|--verbose)
            VERBOSE=1
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "[!] Unknown option: $arg"
            echo "Run '$0 --help' for usage."
            exit 1
            ;;
        *)
            DOMAINS+=("$arg")
            ;;
    esac
done

if [[ ${#DOMAINS[@]} -lt 1 ]]; then
    echo "Usage: $0 [-v|--verbose] domain1.com [domain2.com ...]"
    echo "Run '$0 --help' for more information."
    exit 1
fi

# ---- Verbose-aware command runner ----
# run_step "description" "shell command string"
# In verbose mode: prints the command and lets all output through.
# In quiet mode: only shows the description, suppresses stdout/stderr of the command.
run_step() {
    local desc="$1"
    local cmd="$2"

    echo "  [-] $desc"
    if [[ $VERBOSE -eq 1 ]]; then
        echo "      \$ $cmd"
        eval "$cmd"
    else
        eval "$cmd" >/dev/null 2>&1
    fi
}

check_deps() {
    local missing=()
    for bin in assetfinder subfinder amass dnsx httpx katana waybackurls gau hakcheckurl anew uro curl; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "[!] Missing tools: ${missing[*]}"
        echo "    Install them before running this script (go install ... or apt/brew)."
        exit 1
    fi
}

run_recon() {
    local domain="$1"
    local dir="$BASE_DIR/$domain"

    echo "==============================================="
    echo "[*] Target: $domain"
    echo "[*] Output: $dir"
    echo "[*] Verbose: $([[ $VERBOSE -eq 1 ]] && echo on || echo off)"
    echo "==============================================="

    mkdir -p "$dir"/{subs,live,js,params,findings}

    # -----------------------------------------------------------
    # STAGE 1: Subdomain Enumeration
    # -----------------------------------------------------------
    echo "[*] Stage 1: Subdomain enumeration"

    local subs_out="$dir/subs/${domain}.txt"
    touch "$subs_out"

    run_step "assetfinder" \
        "assetfinder --subs-only \"$domain\" | anew \"$subs_out\""

    run_step "subfinder" \
        "subfinder -d \"$domain\" -all -silent | anew \"$subs_out\""

    run_step "amass (passive)" \
        "amass enum -passive -d \"$domain\" | anew \"$subs_out\""

    run_step "crt.sh" \
        "curl -s \"https://crt.sh/?q=%25.${domain}\" | grep -oE \"[A-Za-z0-9._-]+\\.${domain}\" | sed 's/\\*\\.//g' | sort -u | anew \"$subs_out\""

    sort -u "$subs_out" -o "$subs_out"
    echo "  [+] $(wc -l < "$subs_out") unique subdomains -> $subs_out"

    echo "[*] DNS resolving live subdomains (dnsx)"
    run_step "dnsx" \
        "dnsx -l \"$subs_out\" -silent -o \"$dir/subs/resolved.txt\""
    echo "  [+] $(wc -l < "$dir/subs/resolved.txt" 2>/dev/null || echo 0) resolved -> $dir/subs/resolved.txt"

    echo "[*] Priority subdomains (api./admin./internal./dev./staging./auth./pay./money./chat.):"
    grep -E '^(api|admin|internal|dev|staging|auth|pay|money|chat)\.' "$dir/subs/resolved.txt" 2>/dev/null \
        | tee "$dir/findings/priority_subs.txt" | sed 's/^/    /'

    # -----------------------------------------------------------
    # STAGE 2: Live Host Discovery
    # -----------------------------------------------------------
    echo "[*] Stage 2: Live host discovery (httpx)"

    if [[ ! -s "$dir/subs/resolved.txt" ]]; then
        echo "  [!] No resolved hosts, skipping httpx"
    else
        run_step "httpx" \
            "httpx -l \"$dir/subs/resolved.txt\" -rl 50 -threads 20 -timeout 10 -retries 2 -random-agent -title -tech-detect -status-code -content-length -follow-host-redirects -o \"$dir/live/httpx_output.txt\""

        grep '\[200\]' "$dir/live/httpx_output.txt" > "$dir/live/200s.txt" 2>/dev/null
        grep -E '\[(401|403)\]' "$dir/live/httpx_output.txt" > "$dir/live/auth_required.txt" 2>/dev/null

        awk '{print $1}' "$dir/live/httpx_output.txt" > "$dir/live/alive_urls.txt" 2>/dev/null
        sort -u "$dir/live/alive_urls.txt" -o "$dir/live/alive_urls.txt"

        echo "  [+] $(wc -l < "$dir/live/alive_urls.txt" 2>/dev/null || echo 0) live hosts -> $dir/live/alive_urls.txt"
        echo "  [+] $(wc -l < "$dir/live/200s.txt" 2>/dev/null || echo 0) hosts responding 200"
        echo "  [+] $(wc -l < "$dir/live/auth_required.txt" 2>/dev/null || echo 0) hosts requiring auth (401/403)"
    fi

    # -----------------------------------------------------------
    # STAGE 3: URL Collection & Crawling
    # -----------------------------------------------------------
    echo "[*] Stage 3: URL collection & crawling"

    if [[ -s "$dir/live/alive_urls.txt" ]]; then
        run_step "katana (active crawl, depth 5, JS crawl)" \
            "katana -list \"$dir/live/alive_urls.txt\" -d 5 -js-crawl -jsl -silent -rate-limit 20 -o \"$dir/js/katana_urls.txt\""
        sort -u "$dir/js/katana_urls.txt" -o "$dir/js/katana_urls.txt" 2>/dev/null
        echo "      $(wc -l < "$dir/js/katana_urls.txt" 2>/dev/null || echo 0) URLs found"
    else
        echo "  [!] No alive URLs, skipping katana"
    fi

    local params_out="$dir/params/${domain}_urls.txt"
    touch "$params_out"

    run_step "gau" \
        "gau --subs \"$domain\" | hakcheckurl | anew \"$params_out\""

    run_step "waybackurls" \
        "waybackurls \"$domain\" | hakcheckurl | anew \"$params_out\""

    sort -u "$params_out" -o "$params_out"
    echo "  [+] $(wc -l < "$params_out") historical URLs -> $params_out"

    # -----------------------------------------------------------
    # Merge, filter static assets, and normalize
    # -----------------------------------------------------------
    echo "[*] Merging & cleaning all URLs"

    run_step "merge + filter static assets" \
        "cat \"$dir\"/live/*.txt \"$dir\"/params/*.txt \"$dir\"/js/*.txt 2>/dev/null | sort -u | grep -vE '\\.(css|jpg|jpeg|png|gif|svg|woff|woff2|ttf|ico)(\\?|\$)' | anew \"$dir/all_urls.txt\""

    run_step "normalize (uro)" \
        "cat \"$dir/all_urls.txt\" | uro | anew \"$dir/clean_urls.txt\""

    echo "  [+] $(wc -l < "$dir/all_urls.txt" 2>/dev/null || echo 0) total URLs -> $dir/all_urls.txt"
    echo "  [+] $(wc -l < "$dir/clean_urls.txt" 2>/dev/null || echo 0) normalized URLs -> $dir/clean_urls.txt"

    echo "[+] Done with $domain"
    echo
}

check_deps

if [[ ! -d "$BASE_DIR" ]]; then
    echo "[*] Creating base recon directory: $BASE_DIR"
    mkdir -p "$BASE_DIR"
fi

for domain in "${DOMAINS[@]}"; do
    run_recon "$domain"
done

echo "[*] All targets complete. Results under: $BASE_DIR/<domain>/"
echo "    Main hunting dataset: $BASE_DIR/<domain>/clean_urls.txt"
echo "    Feed into: gf, nuclei, dalfox, qsreplace, sqlmap, etc."
