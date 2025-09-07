
import re

TAKEOVER_PATTERNS = [
    # domain takeover fingerprints (simplified)
    {"name":"GitHub Pages","cname":"github.io","body":r"404 Not Found|There isn't a GitHub Pages site here"},
    {"name":"Amazon S3","cname":"amazonaws.com","body":r"The specified bucket does not exist"},
    {"name":"Heroku","cname":"herokudns.com","body":r"No such app"},
    {"name":"Azure","cname":"azurewebsites.net","body":r"404 Web Site not found"},
    {"name":"Fastly","cname":"fastly.net","body":r"Fastly error|Unknown Domain"},
    {"name":"Shopify","cname":"myshopify.com","body":r"Sorry, this shop is currently unavailable"},
]

TECH_RULES = [
    {"tech":"WordPress","headers":[("x-powered-by",r"wordpress")],"body":r"wp-content|wp-includes"},
    {"tech":"Joomla","body":r"Joomla! - Open Source Content Management"},
    {"tech":"Drupal","body":r"drupal.settings"},
    {"tech":"React","body":r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__"},
    {"tech":"Angular","body":r"ng-version|angular.io"},
    {"tech":"Vue","body":r"__VUE_DEVTOOLS_GLOBAL_HOOK__"},
]

BUCKET_GUESSERS = [
    {"provider":"s3","regex":r"([a-z0-9.-]{3,63})\.s3\.amazonaws\.com"},
    {"provider":"gcs","regex":r"storage\.googleapis\.com/([a-z0-9._-]{3,63})"},
    {"provider":"azure","regex":r"([a-z0-9]{3,24})\.blob\.core\.windows\.net"},
]

def detect_takeover(cname_chain: str, body: str):
    body = body or ""
    cname_chain = (cname_chain or "").lower()
    for fp in TAKEOVER_PATTERNS:
        if fp["cname"] in cname_chain and re.search(fp["body"], body, re.I):
            return ("High", fp["name"])
    return ("None", None)

def detect_technologies(headers, body: str):
    found = set()
    h = {k.lower(): (v or "").lower() for k,v in (headers or {}).items()}
    for rule in TECH_RULES:
        ok = False
        if "headers" in rule:
            for k,pat in rule["headers"]:
                if k in h and re.search(pat, h[k], re.I):
                    ok = True
        if ("body" in rule) and re.search(rule["body"], body or "", re.I):
            ok = True or ok
        if ok:
            found.add(rule["tech"])
    return sorted(found)

def guess_buckets(text: str):
    out = []
    t = text or ""
    for g in BUCKET_GUESSERS:
        m = re.findall(g["regex"], t, re.I)
        for name in set(m):
            out.append({"provider": g["provider"], "name": name})
    return out
