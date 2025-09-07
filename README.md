# Smart Subdomain Validator (SSV) — Enterprise v1.6.2
**created by xiamsec**

> Enterprise‑grade subdomain reconnaissance and validation — one command, full workflow.

- **Massive discovery:** crt.sh, Wayback, CommonCrawl, GitHub* (+ optional subfinder/amass, MassDNS brute)
- **Strict validation (default):** DNS resolve **and** HTTP alive → low noise
- **Rich intel:** TLS CN/SAN + expiry days, WAF/CDN hints, favicon MD5, title/size
- **Detections:** takeover (best‑effort), tech fingerprint (lite), guessed cloud buckets
- **Ports & banners:** async scan of common ports
- **Evidence:** optional screenshots (Playwright), IP enrichment (ASN/Org/Country)
- **Reports:** HTML (dark, readable), JSON/CSV/MD, delta diff between runs
- **Smart auto‑mode:** just `--domain` → SSV picks sane defaults
- **Robustness:** async, concurrency, retries; proxy via env (HTTP_PROXY/HTTPS_PROXY); graceful fallbacks

\* GitHub search requires `GITHUB_TOKEN`. IP enrichment requires `IPINFO_TOKEN`. External tools (subfinder/amass/massdns) are optional.

---

## Table of Contents
- [Install](#install)
- [Quick Start](#quick-start)
- [Recommended Recipes](#recommended-recipes)
- [Flags Reference](#flags-reference)
- [Environment Variables](#environment-variables)
- [Outputs](#outputs)
- [Troubleshooting](#troubleshooting)
- [Performance Tips](#performance-tips)
- [Legal & Safety](#legal--safety)

---

## Install
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
# (optional) Screenshots:
# pip install playwright && playwright install
```

<details>
<summary><b>Optional external tools</b></summary>

- `subfinder`, `amass` → auto‑detected in smart mode
- `massdns` + resolvers + wordlist → huge scale brute discovery
</details>

---

## Quick Start
```bash
# Smart auto‑mode (strict filter): low-noise results
python ssv.py --domain example.com

# Investigation‑friendly (more results + HTML report)
python ssv.py --domain example.com \
  --deep --use-crtsh --use-wayback --use-commoncrawl \
  --timeout 15 --retries 2 --no-verify-ssl --loose \
  --out-html out/report.html
```

> **Why no results sometimes?** In strict mode, a row is kept **only if** DNS resolve **and** HTTP alive both succeed. Use `--loose` to inspect what failed and why.

---

## Recommended Recipes

**Enterprise Sweep (all evidence on):**
```bash
python ssv.py --domain target.com \
  --deep --use-crtsh --use-wayback --use-commoncrawl \
  --takeover --tech --buckets --ports --screens --enrich \
  --timeout 15 --retries 2 --no-verify-ssl --loose \
  --out-json out/results.json --out-csv out/results.csv \
  --out-md out/results.md --out-html out/report.html
```

**MassDNS brute (if you have massdns + resolvers + wordlist):**
```bash
python ssv.py --domain target.com \
  --massdns /usr/local/bin/massdns --resolvers resolvers.txt --brute subs.txt \
  --deep --loose --out-html out/massdns_report.html
```

**Focus ports & techs (quick recon):**
```bash
python ssv.py --domain target.com \
  --deep --use-crtsh --ports --tech --out-html out/ports_tech.html
```

**Delta between two runs:**
```bash
python ssv.py --diff out/old.json out/results.json
```

---

## Flags Reference

| Flag | Purpose | Default | Notes |
|---|---|---:|---|
| `--domain example.com` | Target root domain (repeatable) | – | You can supply multiple `--domain` flags |
| `--input file.txt` | Candidate list (one per line) | – | Merged with discovered candidates |
| `--include-root` | Also check root domain | `False` | Useful for the main site |
| `--use-crtsh` `--use-wayback` `--use-commoncrawl` `--use-github` | Passive sources | `False` (auto in smart mode) | GitHub needs `GITHUB_TOKEN` |
| `--use-subfinder` `--use-amass` | External tools | `False` (auto if installed) | Improves coverage |
| `--massdns` `--resolvers` `--brute` | Huge brute with MassDNS | – | Requires binary + resolver list + wordlist |
| `--common` `--deep` | Built‑in common prefixes / stronger discovery | `False` | `--deep` implies common prefixes |
| `--timeout 15` `--retries 2` | Network tuning | `8`, `1` | Increase for slow hosts |
| `--concurrency 120` | Parallelism | `60` | Raise gradually |
| `--loose` | Keep entries that pass DNS **or** HTTP | `False` | Great for investigation |
| `--no-verify-ssl` | Skip TLS verification | `False` | Helps on misconfigured certs |
| `--ports` `--ports-list 80,443,8080` | Port scan + banner | `False` | Common ports by default |
| `--takeover` | Subdomain takeover detector | `False` | Best‑effort fingerprints |
| `--tech` | Technology fingerprint (lite) | `False` | Body/headers rules |
| `--buckets` | Guess S3/GCS/Azure buckets | `False` | Regex‑based hints |
| `--screens` `--screens-out` `--screens-concurrency` | Screenshots | `False` | Needs Playwright |
| `--enrich` | IP ASN/Org/Country | `False` | Needs `IPINFO_TOKEN` |
| `--out-json` `--out-csv` `--out-md` `--out-html` | Reports | – | HTML is a readable dashboard |
| `--diff old.json new.json` | Show Added/Removed | – | Track changes across runs |
| `--silent` | Minimal console output | `False` | CI‑friendly |

---

## Environment Variables

```bash
# Proxy (httpx 0.28+ uses env)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=$HTTP_PROXY

# GitHub code search (for --use-github)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxx

# IP enrichment (for --enrich)
export IPINFO_TOKEN=xxxxxxxxxxxxxxxxx
```

> **Note:** In v1.6.2, proxies are supported via environment variables only (no `proxies=` kwarg in the client).

---

## Outputs

- **HTML**: `--out-html out/report.html` (dark, sortable-like table + summary counts)
- **JSON/CSV/MD**: machine‑readable & shareable
- Core fields: `subdomain`, `resolved_ips`, `http_alive`, `scheme`, `status`, `final_url`, `server`, `title`, `content_length`, `tls_cn`, `tls_san`, `tls_days_left`, `favicon_md5`, `waf`, `ports`, `technologies`, `takeover_risk`, `takeover_fp`, `screens_path`

Example CSV header:
```
subdomain,resolved_ips,http_alive,scheme,status,final_url,server,title,content_length,tls_cn,tls_san,tls_days_left,favicon_md5,waf,ports,technologies,takeover_risk,takeover_fp,screens_path
```

---

## Troubleshooting

- **Empty table (no rows):** Strict mode filters out entries failing DNS+HTTP. Re‑run with `--loose` and increase `--timeout 15 --retries 2`; add `--no-verify-ssl`.  
- **SSL errors:** Use `--no-verify-ssl` for investigation; fix later if needed.  
- **Behind WAF/CDN:** HTTP might be 403/5xx but still “Alive”. Use `--loose` to see all; check WAF hint.  
- **Network/Proxy:** Set `HTTP_PROXY/HTTPS_PROXY` env (no `--proxies` kwarg).  
- **Few candidates:** Add passive sources; or use MassDNS brute.  
- **Wildcard DNS detected:** SSV enforces HTTP alive for accuracy (notice shown).  
- **Screenshots failing:** Ensure Playwright is installed and `playwright install` was run once.

---

## Performance Tips

- Increase `--concurrency` gradually: `60 → 90 → 120`  
- Tweak `--timeout`/`--retries` for slow regions  
- Focus ports via `--ports-list 80,443,8080,8443,8000`  
- Use MassDNS brute for very large scopes

---

## Legal & Safety

Use this tool **only** on assets you **own** or have explicit **permission** to test. Respect rate limits, local laws, and responsible disclosure guidelines.

---

**Credits:** built & designed by **xiamsec**. PRs and feedback welcome.
