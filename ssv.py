import argparse, asyncio, csv, json, os, re, shlex, socket, ssl, subprocess, sys, time, hashlib
from typing import Iterable, List, Dict, Any, Optional, Set, Tuple

import httpx
try:
    import aiodns
except Exception:
    aiodns = None

from rich.console import Console
from rich.table import Table
import rich
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from report_html import build_html
from fingerprints import detect_takeover, detect_technologies, guess_buckets
from screenshots import capture_screenshot
from enrich import enrich_ip
from diff_tool import diff_json

BANNER = r'''
   ____                  _         _     _           _             _       _           _ _           _           
  / ___| _ __ ___   __ _| |_ _   _| |__ | |__   __ _| |_ ___  _ __(_) __ _| |__   __ _(_) |__  _   _| | ___  ___ 
  \___ \| '_ ` _ \ / _` | __| | | | '_ \| '_ \ / _` | __/ _ \| '__| |/ _` | '_ \ / _` | | '_ \| | | | |/ _ \/ __|
   ___) | | | | | | (_| | |_| |_| | |_) | | | | (_| | || (_) | |  | | (_| | | | | (_| | | |_) | |_| | |  __/\__ \
  |____/|_| |_| |_|\__,_|\__|\__,_|_.__/|_| |_|\__,_|\__\___/|_|  |_|\__, |_| |_|\__,_|_|_.__/ \__,_|_|\___||___/
                                                                    |___/                                         
                                   created by xiamsec (v1.6.2 Enterprise)
'''

console = Console()

# Note: Proxy via env only (HTTP_PROXY / HTTPS_PROXY) for httpx>=0.28 compatibility

def banner(silent=False, subtitle="fast • async • accurate • enterprise"):
    if not silent:
        console.print(Panel.fit(BANNER, border_style="cyan", title="Smart Subdomain Validator", subtitle=subtitle))

def norm_domain(d: str) -> str:
    s = (d or "").strip().lower()
    # strip scheme
    s = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', s)
    # host only
    s = s.split('/')[0]
    # strip trailing dot/slash
    s = s.strip('.').strip('/')
    return s

def unique(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in seq:
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

def chunked(iterable, n):
    it = iter(iterable)
    while True:
        chunk = []
        try:
            for _ in range(n):
                chunk.append(next(it))
        except StopIteration:
            if chunk:
                yield chunk
            break
        else:
            yield chunk

def which(n: str) -> Optional[str]:
    from shutil import which as w
    return w(n)

# ---------------- Sources ----------------
async def fetch_crtsh(client, domain: str) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = await client.get(url, headers={'User-Agent': 'SSV/1.6.2'}, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subs: Set[str] = set()
        for row in data:
            name_value = row.get("name_value", "")
            for entry in name_value.splitlines():
                entry = entry.strip().lower()
                if entry.startswith("*."):
                    entry = entry[2:]
                if entry.endswith(domain) and entry.count(".") >= domain.count("."):
                    subs.add(entry)
        return subs
    except Exception:
        return set()

async def fetch_wayback(client, domain: str) -> Set[str]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = await client.get(url, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subs = set()
        for row in data[1:]:
            u = row[0]
            try:
                host = u.split('/')[2].lower()
                if host.endswith(domain):
                    subs.add(host)
            except Exception:
                pass
        return subs
    except Exception:
        return set()

async def fetch_commoncrawl(client, domain: str) -> Set[str]:
    try:
        r = await client.get(f"https://index.commoncrawl.org/CC-MAIN-2024-14-index?url=*.{domain}&output=json", timeout=20)
        if r.status_code != 200:
            return set()
        subs = set()
        for line in r.text.splitlines():
            try:
                j = json.loads(line)
                host = j.get("url","").split('/')[2].lower()
                if host.endswith(domain):
                    subs.add(host)
            except Exception:
                pass
        return subs
    except Exception:
        return set()

async def fetch_github(client, domain: str, gh_token: Optional[str]) -> Set[str]:
    if not gh_token:
        return set()
    headers = {"Authorization": f"token {gh_token}", "Accept":"application/vnd.github.text-match+json"}
    q = f'"{domain}" in:file'
    url = "https://api.github.com/search/code"
    subs = set()
    try:
        r = await client.get(url, params={"q": q, "per_page": 50}, headers=headers, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        for item in data.get("items", []):
            tm = item.get("text_matches", [])
            for m in tm:
                frag = m.get("fragment","").lower()
                for part in frag.split():
                    if part.endswith(domain):
                        subs.add(part.strip("',\"()[]{}<>"))
        return subs
    except Exception:
        return set()

def call(cmd: str) -> Set[str]:
    try:
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=90)
        if p.returncode != 0:
            return set()
        return set(line.strip().lower() for line in p.stdout.splitlines() if line.strip())
    except Exception:
        return set()

def gather_from_tools(domain: str, use_subfinder: bool, use_amass: bool) -> Set[str]:
    subs: Set[str] = set()
    if use_subfinder and which("subfinder"):
        subs |= call(f"subfinder -silent -d {shlex.quote(domain)}")
    if use_amass and which("amass"):
        subs |= call(f"amass enum -passive -d {shlex.quote(domain)}")
    return subs

def run_massdns(domain: str, wordlist: str, resolvers: str, massdns_path: str) -> Set[str]:
    if not (massdns_path and os.path.isfile(massdns_path) and os.path.isfile(wordlist) and os.path.isfile(resolvers)):
        return set()
    out = call(f"{shlex.quote(massdns_path)} -r {shlex.quote(resolvers)} -t A -o S -w - {shlex.quote(wordlist)}")
    subs = set()
    for line in out:
        parts = line.split()
        if parts and parts[0].endswith("."):
            host = parts[0][:-1]
            if host.endswith(domain):
                subs.add(host)
    return subs

# ---------------- DNS/HTTP/TLS ----------------
async def resolve_dns_async(resolver, host: str) -> List[str]:
    if not resolver:
        ips: Set[str] = set()
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            for af, socktype, proto, canonname, sa in infos:
                ips.add(sa[0])
        except Exception:
            pass
        return list(ips)
    ips: Set[str] = set()
    try:
        a = await resolver.gethostbyname(host, socket.AF_INET)
        ips |= set(a.addresses)
    except Exception:
        pass
    try:
        aaaa = await resolver.gethostbyname(host, socket.AF_INET6)
        ips |= set(aaaa.addresses)
    except Exception:
        pass
    return list(ips)

async def detect_wildcard(resolver, domain: str) -> Optional[Set[str]]:
    import random, string
    def rl(n=8): return "".join(random.choice(string.ascii_lowercase) for _ in range(n))
    sets = []
    for _ in range(3):
        host = f"{rl()}.{domain}"
        sets.append(set(await resolve_dns_async(resolver, host)))
    if all(sets) and len(set(tuple(sorted(s)) for s in sets)) == 1:
        return set(sets[0])
    return None

async def http_probe(client, host: str, verify_ssl: bool, timeout: int, retries: int):
    schemes = ["https","http"]
    for scheme in schemes:
        url = f"{scheme}://{host}"
        attempt = 0
        while attempt <= retries:
            try:
                headers = {'User-Agent': '', 'Accept': '*/*'}
                r = await client.get(url, follow_redirects=True, timeout=timeout, headers=headers)
                status = r.status_code
                final_url = str(r.url)
                server = r.headers.get("server")
                title = None
                m = re.search(r"<title>(.*?)</title>", r.text or "", re.I|re.S)
                if m:
                    title = m.group(1).strip()[:120]
                try:
                    clen = int(r.headers.get("content-length","0") or "0")
                except Exception:
                    clen = None
                return True, scheme, status, final_url, server, title, clen, r.headers, r.text
            except Exception:
                attempt += 1
    return False, None, None, None, None, None, None, {}, ""

def tls_info(host: str, port: int = 443, timeout: int = 6):
    cn = None; sans = []; days_left=None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                for attr in cert.get("subject", ()):
                    for k,v in attr:
                        if k=="commonName": cn=v
                for (typ, value) in cert.get("subjectAltName", ()):
                    if typ=="DNS": sans.append(value)
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp = time.mktime(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
                        days_left = int((exp - time.time())/86400)
                    except Exception:
                        pass
    except Exception:
        pass
    return cn, sans, days_left

async def favicon_md5(client, scheme: str, host: str, timeout: int):
    try:
        r = await client.get(f"{scheme}://{host}/favicon.ico", timeout=timeout)
        if r.status_code==200 and r.content:
            return hashlib.md5(r.content).hexdigest()
    except Exception:
        pass
    return None

def detect_waf(headers: Dict[str,str]) -> Optional[str]:
    h = {k.lower(): (v or "").lower() for k,v in (headers or {}).items()}
    if "cf-ray" in h or "cf-cache-status" in h or ("server" in h and "cloudflare" in h["server"]):
        return "Cloudflare (WAF/CDN)"
    if "akamai" in (h.get("server","")+h.get("via","")):
        return "Akamai (CDN)"
    if "x-sucuri-id" in h or "x-sucuri-cache" in h:
        return "Sucuri (WAF)"
    if "x-firewall" in h or "x-waf" in h:
        return "Generic WAF"
    return None

# Ports
COMMON_PORTS = [80,443,22,21,25,110,143,587,993,995,3306,8080,8443,8000,53]

async def probe_port(ip: str, port: int, timeout: float = 1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            writer.write(b"\r\n"); await asyncio.wait_for(writer.drain(), timeout=0.5)
            data = await asyncio.wait_for(reader.read(128), timeout=0.8)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
        return {"ip": ip, "port": port, "banner": banner}
    except Exception:
        return None

async def scan_ports(ips: List[str], ports: List[int], concurrency: int = 200) -> List[Dict[str,Any]]:
    sem = asyncio.Semaphore(concurrency)
    out = []
    async def task(ip, p):
        async with sem:
            r = await probe_port(ip, p)
            if r: out.append(r)
    coros = []
    for ip in ips[:5]:
        for p in ports:
            coros.append(task(ip,p))
    await asyncio.gather(*coros, return_exceptions=True)
    seen=set(); res=[]
    for r in out:
        key=(r["ip"], r["port"])
        if key not in seen:
            seen.add(key); res.append(r)
    return res

# ---------------- Core ----------------
async def collect(domains: List[str], args, client) -> List[str]:
    cands: Set[str] = set()
    if args.input and os.path.isfile(args.input):
        with open(args.input,"r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                s=line.strip().lower()
                if s: cands.add(s)
    for d in domains:
        if args.include_root: cands.add(d)
        if args.use_crtsh:    cands |= await fetch_crtsh(client,d)
        if args.use_wayback:  cands |= await fetch_wayback(client,d)
        if args.use_commoncrawl: cands |= await fetch_commoncrawl(client,d)
        if args.use_github:   cands |= await fetch_github(client,d, os.getenv("GITHUB_TOKEN"))
        if args.use_subfinder or args.use_amass:
            cands |= gather_from_tools(d, args.use_subfinder, args.use_amass)
        if args.massdns and args.brute and args.resolvers:
            cands |= run_massdns(d, args.brute, args.resolvers, args.massdns)
        if args.common or args.deep:
            for w in ["www","api","dev","staging","test","beta","admin","portal","cdn","static","app","mail","vpn","m","edge","files","data","prod"]:
                cands.add(f"{w}.{d}")
    if domains:
        suffixes=tuple(domains)
        cands = {c for c in cands if c.endswith(suffixes)}
    return unique(sorted(cands))

async def validate_one(host: str, client, resolver, args, ports_list: List[int]) -> Optional[Dict[str,Any]]:
    ips = await resolve_dns_async(resolver, host)
    ok, scheme, status, final_url, server, title, clen, headers, body = await http_probe(client, host, not args.no_verify_ssl, args.timeout, args.retries)
    tls_cn=tls_san=[]; tls_days=None
    if ok and scheme=="https":
        cn, sans, days = tls_info(host)
        tls_cn, tls_san, tls_days = cn, sans, days
    fav=None
    if ok and scheme:
        fav = await favicon_md5(client, scheme, host, args.timeout)
    waf = detect_waf(headers)
    takeover_risk=None; takeover_fp=None
    if args.takeover and ok:
        cname_chain = ",".join(tls_san or [])
        risk, fp = detect_takeover(cname_chain, body or "")
        takeover_risk, takeover_fp = risk, fp
    techs=None
    if args.tech and ok:
        techs = detect_technologies(headers, body)
    port_listings=[]
    if args.ports and ips:
        port_listings = await scan_ports(ips, ports_list)
    buckets=None
    if args.buckets and ok:
        buckets = guess_buckets((body or "") + " " + (final_url or ""))
    if not args.loose:
        if not ips or not ok:
            return None
    return {
        "subdomain": host,
        "resolved_ips": ips,
        "http_alive": bool(ok),
        "scheme": scheme,
        "status": status,
        "final_url": final_url,
        "server": server,
        "title": title,
        "content_length": clen,
        "tls_cn": tls_cn,
        "tls_san": tls_san,
        "tls_days_left": tls_days,
        "favicon_md5": fav,
        "waf": waf,
        "ports": port_listings,
        "technologies": techs,
        "takeover_risk": takeover_risk,
        "takeover_fp": takeover_fp,
        "buckets": buckets,
        "screens_path": None,
    }

async def main_async(args):
    subtitle = "fast • async • accurate • enterprise"
    banner(args.silent, subtitle)
    # smart auto-mode
    if not any([args.use_crtsh, args.use_wayback, args.use_commoncrawl, args.use_github, args.use_subfinder, args.use_amass, args.massdns, args.input]) and not args.common and not args.deep:
        args.use_crtsh=True; args.common=True; args.include_root=True
        if which("subfinder"): args.use_subfinder=True
        if which("amass"): args.use_amass=True
        console.rule("[bold magenta]smart auto-mode[/bold magenta]")
    limits = httpx.Limits(max_keepalive_connections=args.concurrency, max_connections=args.concurrency)
    async with httpx.AsyncClient(limits=limits, verify=(not args.no_verify_ssl)) as client:
        resolver=None
        if aiodns:
            try:
                resolver = aiodns.DNSResolver()
            except Exception:
                resolver=None
        if not args.silent:
            console.rule("[bold cyan]Collecting Candidates")
        domains_raw = args.domain or []
        domains = [norm_domain(d) for d in domains_raw]
        # gentle note if slash/path
        for d in domains_raw:
            if '/' in d.strip():
                console.print("[yellow]Note:[/yellow] removed trailing path or slash from domain input.")
                break
        cands = await collect(domains, args, client)
        if not cands:
            console.print("[yellow]No candidates found.[/yellow]"); return
        for d in domains:
            wi = await detect_wildcard(resolver, d)
            if wi and not args.silent:
                console.print(f"[yellow]Wildcard DNS detected for {d}. Strict mode will require HTTP alive.[/yellow]")
        if not args.silent:
            console.print(f"[green]Total candidates:[/green] {len(cands)}")
            console.rule("[bold cyan]Validating")
        sem = asyncio.Semaphore(args.concurrency)
        results=[]
        async def task(h):
            async with sem:
                r = await validate_one(h, client, resolver, args, args.ports_list or COMMON_PORTS)
                if r:
                    results.append(r)
        with Progress(SpinnerColumn(), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn(), TextColumn("{task.completed}/{task.total}"), transient=True, disable=args.silent, console=console) as progress:
            t = progress.add_task("Validating", total=len(cands))
            coros = [task(h) for h in cands]
            for batch in chunked(coros, args.concurrency*2):
                await asyncio.gather(*batch, return_exceptions=True)
                progress.update(t, advance=len(batch))
        # screenshots
        if args.screens:
            if not args.silent: console.rule("[bold cyan]Screenshots")
            os.makedirs(args.screens_out, exist_ok=True)
            async def shot(row):
                if row.get("http_alive"):
                    url = row.get("final_url") or f"{row.get('scheme')}://{row.get('subdomain')}"
                    path = os.path.join(args.screens_out, f"{row['subdomain'].replace('/','_')}.png")
                    got = await capture_screenshot(url, path, timeout=args.timeout*1000)
                    if got: row["screens_path"]=got
            with Progress(SpinnerColumn(), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn(), transient=True, disable=args.silent, console=console) as progress:
                t = progress.add_task("Capturing", total=len(results))
                coros = [shot(r) for r in results]
                for batch in chunked(coros, max(1,args.screens_concurrency)):
                    await asyncio.gather(*batch, return_exceptions=True)
                    progress.update(t, advance=len(batch))
        # enrich
        if args.enrich:
            if not args.silent: console.rule("[bold cyan]Enrich IPs")
            async def add_enrich(row):
                for ip in row.get("resolved_ips") or []:
                    e = await enrich_ip(ip)
                    if e: row.update(e)
            await asyncio.gather(*(add_enrich(r) for r in results))
        results.sort(key=lambda x:(not x["http_alive"], x["subdomain"]))
        if not args.silent:
            table = Table(title="SSV Enterprise — Results", show_lines=False)
            table.add_column("Subdomain", style="cyan", no_wrap=True)
            table.add_column("HTTP", justify="center")
            table.add_column("Code", justify="right")
            table.add_column("Scheme", justify="center")
            table.add_column("IPs", style="magenta")
            table.add_column("TLS CN", style="green")
            table.add_column("Server", style="yellow")
            table.add_column("Title", style="white")
            for r in results[:150]:
                table.add_row(
                    r["subdomain"],
                    "Alive" if r["http_alive"] else "Dead",
                    str(r["status"] or ""),
                    r["scheme"] or "",
                    ", ".join(r["resolved_ips"][:3]),
                    r["tls_cn"] or "",
                    (r["server"] or ""),
                    (r["title"] or "")[:40],
                )
            console.print(table)
            if len(results)>150:
                console.print(f"[dim]...and {len(results)-150} more (see outputs).[/dim]")
        if not any([args.out_json,args.out_csv,args.out_md,args.out_html]):
            os.makedirs("out",exist_ok=True)
            args.out_json = os.path.join("out", f"{domains[0]}_results.json")
        if args.out_json:
            os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
            with open(args.out_json,"w",encoding="utf-8") as f:
                json.dump(results,f,ensure_ascii=False,indent=2)
            if not args.silent: console.print(f"[bold green]Saved JSON:[/bold green] {args.out_json}")
        if args.out_csv:
            os.makedirs(os.path.dirname(args.out_csv), exist_ok=True)
            with open(args.out_csv,"w",newline="",encoding="utf-8") as f:
                w=csv.writer(f)
                w.writerow(["subdomain","resolved_ips","http_alive","scheme","status","final_url","server","title","content_length","tls_cn","tls_san","tls_days_left","favicon_md5","waf","ports","technologies","takeover_risk","takeover_fp","screens_path"])
                for r in results:
                    w.writerow([
                        r["subdomain"], ";".join(r.get("resolved_ips") or []), int(r["http_alive"]), r.get("scheme") or "", r.get("status") or "",
                        r.get("final_url") or "", r.get("server") or "", r.get("title") or "", r.get("content_length") or 0,
                        r.get("tls_cn") or "", ";".join(r.get("tls_san") or []), r.get("tls_days_left") or "",
                        r.get("favicon_md5") or "", r.get("waf") or "",
                        ";".join(f"{p.get('ip')}:{p.get('port')}" for p in (r.get("ports") or [])),
                        ",".join(r.get("technologies") or []),
                        r.get("takeover_risk") or "", r.get("takeover_fp") or "", r.get("screens_path") or ""
                    ])
            if not args.silent: console.print(f"[bold green]Saved CSV:[/bold green] {args.out_csv}")
        if args.out_md:
            os.makedirs(os.path.dirname(args.out_md), exist_ok=True)
            with open(args.out_md,"w",encoding="utf-8") as f:
                f.write("| Subdomain | HTTP | Code | Scheme | IPs | TLS CN | Server | Title | Ports | Takeover |\n")
                f.write("|---|---:|---:|:---:|---|---|---|---|---|---|\n")
                for r in results:
                    f.write(f"| {r['subdomain']} | {'Alive' if r['http_alive'] else 'Dead'} | {r['status'] or ''} | {r['scheme'] or ''} | {', '.join(r['resolved_ips'])} | {r['tls_cn'] or ''} | {r['server'] or ''} | {(r['title'] or '').replace('|',' ')} | {','.join(str(p.get('port')) for p in (r.get('ports') or []))} | {r.get('takeover_risk') or ''} |\n")
            if not args.silent: console.print(f"[bold green]Saved Markdown:[/bold green] {args.out_md}")
        if args.out_html:
            os.makedirs(os.path.dirname(args.out_html), exist_ok=True)
            html = build_html(results, {"title":"SSV Enterprise Report","domains": domains})
            with open(args.out_html,"w",encoding="utf-8") as f:
                f.write(html)
            if not args.silent: console.print(f"[bold green]Saved HTML:[/bold green] {args.out_html}")
        if args.diff and len(args.diff)==2:
            d = diff_json(args.diff[0], args.diff[1])
            console.rule("[bold cyan]Diff")
            console.print({"added": d["added"], "removed": d["removed"]})

def parse():
    p = argparse.ArgumentParser(
        prog="ssv.py",
        description="Smart Subdomain Validator — Enterprise (v1.6.2) created by xiamsec",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--domain", action="append", help="Target root domain (repeatable)")
    p.add_argument("--input", help="Read candidates from file (one per line)")
    # discovery
    p.add_argument("--include-root", action="store_true", help="Include root domain")
    p.add_argument("--use-crtsh", action="store_true", help="Use crt.sh")
    p.add_argument("--use-wayback", action="store_true", help="Use Wayback Machine")
    p.add_argument("--use-commoncrawl", action="store_true", help="Use CommonCrawl index")
    p.add_argument("--use-github", action="store_true", help="Use GitHub code search (needs GITHUB_TOKEN env)")
    p.add_argument("--use-subfinder", action="store_true", help="Use subfinder (if installed)")
    p.add_argument("--use-amass", action="store_true", help="Use amass (if installed)")
    p.add_argument("--massdns", help="Path to massdns binary")
    p.add_argument("--resolvers", help="Resolvers file for massdns")
    p.add_argument("--brute", help="Wordlist for massdns brute")
    p.add_argument("--common", action="store_true", help="Built-in common brute")
    p.add_argument("--deep", action="store_true", help="Stronger discovery (includes common)")
    # validation & perf
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds")
    p.add_argument("--retries", type=int, default=1, help="HTTP retries")
    p.add_argument("--concurrency", type=int, default=60, help="Max concurrent tasks")
    p.add_argument("--loose", action="store_true", help="Include unresolved or HTTP-dead entries")
    p.add_argument("--no-verify-ssl", action="store_true", help="Skip SSL verification")
    p.add_argument("--proxy", help="(Use env: HTTP_PROXY / HTTPS_PROXY) — kept for compatibility")
    # extras
    p.add_argument("--ports", action="store_true", help="Scan common ports on resolved IPs")
    p.add_argument("--ports-list", help="Comma-separated ports (e.g., 80,443,8080)")
    p.add_argument("--takeover", action="store_true", help="Subdomain takeover detector")
    p.add_argument("--tech", action="store_true", help="Technology fingerprint (lite)")
    p.add_argument("--buckets", action="store_true", help="Guess cloud buckets from content/URL")
    p.add_argument("--screens", action="store_true", help="Capture headless screenshots (Playwright)")
    p.add_argument("--screens-out", default="out/screens", help="Screenshots output folder")
    p.add_argument("--screens-concurrency", type=int, default=4, help="Screenshot concurrency")
    p.add_argument("--enrich", action="store_true", help="IP enrichment (requires IPINFO_TOKEN env)")
    # outputs
    p.add_argument("--out-json", help="Save JSON report path")
    p.add_argument("--out-csv", help="Save CSV path")
    p.add_argument("--out-md", help="Save Markdown path")
    p.add_argument("--out-html", help="Save HTML path")
    # diff
    p.add_argument("--diff", nargs=2, metavar=("OLD.json","NEW.json"), help="Show delta between two result files")
    p.add_argument("--silent", action="store_true", help="Minimal console output")
    return p.parse_args()

def main():
    args = parse()
    if not args.domain and not args.input:
        console.print("[red]Provide at least one --domain or --input file.[/red]")
        sys.exit(2)
    # ports
    if args.ports_list:
        try:
            args.ports_list = [int(x.strip()) for x in args.ports_list.split(",") if x.strip()]
        except Exception:
            args.ports_list = COMMON_PORTS
    else:
        args.ports_list = COMMON_PORTS
    # Proxy note (env-based)
    if args.proxy and not os.environ.get("HTTP_PROXY") and not os.environ.get("HTTPS_PROXY"):
        console.print("[yellow]Note:[/yellow] Set proxies via env for httpx 0.28+: export HTTP_PROXY=... / HTTPS_PROXY=...")
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()