# subrecon

A single-script reconnaissance pipeline for bug bounty hunting: subdomain enumeration, live host discovery, and URL collection/crawling — chained together and saved to a clean, per-target output tree.

## What it does

`subrecon.sh` runs three stages against each domain you give it:

1. **Subdomain enumeration** — `assetfinder`, `subfinder`, `amass` (passive), and `crt.sh` are merged and deduplicated, then resolved with `dnsx`. Subdomains matching common high-value patterns (`api.`, `admin.`, `staging.`, `auth.`, etc.) are flagged separately.
2. **Live host discovery** — `httpx` probes every resolved host with tech detection, status codes, and content length, splitting results into hosts that respond `200` and hosts that require auth (`401`/`403`).
3. **URL collection & crawling** — `katana` actively crawls live hosts (including JS parsing), while `gau` and `waybackurls` pull historical URLs. Everything is merged, filtered of static assets, and normalized with `uro` into a final deduplicated dataset.

The result is a ready-to-use URL list you can feed straight into `gf`, `nuclei`, `dalfox`, `qsreplace`, `sqlmap`, or whatever's next in your workflow.

## Requirements

The following tools must be installed and available in your `$PATH`:

| Tool | Purpose |
|---|---|
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain discovery |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |
| [amass](https://github.com/owasp-amass/amass) | Deep passive enumeration |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing + tech detection |
| [katana](https://github.com/projectdiscovery/katana) | Active crawling (incl. JS) |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Historical URLs (Wayback Machine) |
| [gau](https://github.com/lc/gau) | Historical URLs (multiple archives) |
| [hakcheckurl](https://github.com/hakluke/hakcheckurl) | URL liveness filtering |
| [anew](https://github.com/tomnomnom/anew) | Append-only deduplication |
| [uro](https://github.com/s0md3v/uro) | URL list normalization |
| `curl` | crt.sh certificate transparency queries |

Most of the [ProjectDiscovery](https://github.com/projectdiscovery) tools install via `go install`, and the `tomnomnom`/`hakluke` tools do too. Check each repo's README for install instructions.

The script checks for all dependencies on startup and tells you what's missing before doing any work.

## Installation

```bash
git clone https://github.com/subrat243/Subrecon.git
cd Subrecon
chmod +x subrecon.sh
```

## Usage

```bash
./subrecon.sh domain1.com [domain2.com ...]
```

### Options

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Show full output/errors from every tool instead of just step names and result counts |
| `-h`, `--help` | Show the help menu |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `BASE_DIR` | `$HOME/subrecon` | Base directory where results are saved |

### Examples

```bash
# Single target
./subrecon.sh target.com

# Multiple targets in one run
./subrecon.sh target.com second.com third.com

# Verbose mode — watch each tool's raw output
./subrecon.sh -v target.com

# Save results somewhere else
BASE_DIR=/data/recon ./subrecon.sh target.com
```

## Output structure

Each target gets its own directory under `$BASE_DIR`:

```
$BASE_DIR/<domain>/
├── subs/
│   ├── <domain>.txt          # all discovered subdomains, deduped
│   └── resolved.txt          # DNS-resolved (live) subdomains
├── live/
│   ├── httpx_output.txt      # full httpx results (title, tech, status, etc.)
│   ├── alive_urls.txt        # just the live URLs
│   ├── 200s.txt              # hosts responding 200
│   └── auth_required.txt     # hosts responding 401/403
├── js/
│   └── katana_urls.txt       # URLs found via active + JS crawling
├── params/
│   └── <domain>_urls.txt     # historical URLs from gau + waybackurls
├── findings/
│   └── priority_subs.txt     # high-value subdomains (api., admin., staging., etc.)
├── all_urls.txt               # everything merged, deduped, static assets filtered
└── clean_urls.txt             # normalized final dataset — your main hunting file
```

`clean_urls.txt` is the file you'll want to hand off to your next tool in the chain.

## Priority subdomain patterns

The script automatically flags subdomains matching these prefixes into `findings/priority_subs.txt`, since they tend to expose more attack surface:

```
api.  admin.  internal.  dev.  staging.  auth.  pay.  money.  chat.
```

## Notes

- This tool generates real network traffic against target infrastructure (subdomain brute-forcing, active crawling, HTTP probing). **Only run it against domains you are authorized to test** — an active bug bounty program in scope, or explicit written permission.
- Rate limits are conservative by default (`httpx -rl 50`, `katana -rate-limit 20`) to avoid hammering targets, but you should still respect each program's specific scope and rate-limit rules.
- On a large scope, expect 10k–50k+ URLs in `all_urls.txt` before normalization.

## License

MIT — see [LICENSE](LICENSE)
