#!/usr/bin/env python3
"""
input_scanner.py — Bug Bounty Input Point Scanner + XSS Reflection Tester

Phase 1: Crawl subdomains, find <input> tags, forms, iframes, file uploads.
Phase 2 (--xss): For XSS-prone inputs (text/search/url/tel/textarea),
         submit tiny payloads and check if they reflect unescaped in the response.

Usage:
    python3 input_scanner.py -f subdomains.txt
    python3 input_scanner.py -f subdomains.txt --xss
    python3 input_scanner.py -f subdomains.txt --xss --threads 20 --timeout 10
"""

import argparse
import sys
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] Missing dependencies. Run:")
    print("    pip install requests beautifulsoup4 colorama")
    sys.exit(1)


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 15
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# Types where XSS reflection is actually possible
XSS_PROBE_TYPES = {"text", "search", "url", "tel", "email", "number", "textarea"}

BORING_TYPES = {"submit", "button", "reset", "image", "checkbox", "radio"}

# Lightweight XSS probes — chosen to be distinctive & low noise
# We check if they appear unescaped in the response body
XSS_PAYLOADS = [
    # HTML injection check (no JS needed — just sees if tag reflects)
    '<h1>xsstest</h1>',
    # JS alert — classic reflection check
    '<script>alert(1)</script>',
    # Event handler — bypasses some script-tag filters
    '"><img src=x onerror=alert(1)>',
]

# What we look for in the reflected response (unescaped = vulnerable)
REFLECT_SIGNATURES = [
    r'<h1>xsstest</h1>',
    r'<script>alert\(1\)</script>',
    r'onerror=alert\(1\)',
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def normalize_url(subdomain: str) -> list:
    subdomain = subdomain.strip().rstrip("/")
    if subdomain.startswith(("http://", "https://")):
        return [subdomain]
    return [f"https://{subdomain}", f"http://{subdomain}"]


def fetch(url: str, timeout: int, method: str = "GET", data: dict = None) -> requests.Response | None:
    try:
        if method == "POST":
            r = requests.post(url, headers=HEADERS, data=data,
                              timeout=timeout, allow_redirects=True, verify=False)
        else:
            r = requests.get(url, headers=HEADERS, params=data,
                             timeout=timeout, allow_redirects=True, verify=False)
        return r
    except Exception:
        return None


def is_reflected(payload: str, html: str) -> bool:
    """Check if any XSS signature appears unescaped in the response."""
    for sig in REFLECT_SIGNATURES:
        if re.search(sig, html, re.IGNORECASE):
            return True
    # Also direct check — payload appears verbatim
    return payload in html


# ─── Phase 1: Page scan ──────────────────────────────────────────────────────

def scan_page(subdomain: str, timeout: int) -> dict:
    result = {
        "subdomain": subdomain,
        "url":       None,
        "status":    None,
        "inputs":    [],
        "forms":     [],
        "iframes":   [],
        "error":     None,
    }

    response = None
    for url in normalize_url(subdomain):
        response = fetch(url, timeout)
        if response is not None:
            result["url"]    = response.url
            result["status"] = response.status_code
            break

    if response is None:
        result["error"] = "unreachable"
        return result

    if response.status_code >= 400:
        result["error"] = f"HTTP {response.status_code}"
        return result

    soup = BeautifulSoup(response.text, "html.parser")
    base_url = result["url"]

    # ── Inputs ──
    for tag in soup.find_all("input"):
        itype = (tag.get("type") or "text").lower()
        if itype in BORING_TYPES:
            continue
        result["inputs"].append({
            "type":        itype,
            "name":        tag.get("name", ""),
            "id":          tag.get("id", ""),
            "placeholder": tag.get("placeholder", ""),
            "xss_probe":   itype in XSS_PROBE_TYPES,
        })

    for tag in soup.find_all("textarea"):
        result["inputs"].append({
            "type":        "textarea",
            "name":        tag.get("name", ""),
            "id":          tag.get("id", ""),
            "placeholder": tag.get("placeholder", ""),
            "xss_probe":   True,
        })

    # ── Forms (with their own input fields linked) ──
    for form in soup.find_all("form"):
        action  = form.get("action", "")
        method  = (form.get("method") or "GET").upper()
        enctype = form.get("enctype", "")
        full_action = urljoin(base_url, action) if action else base_url

        # Collect all fields inside this specific form
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            itype = (inp.get("type") or "text").lower()
            if itype in BORING_TYPES:
                continue
            fields.append({
                "type":      itype,
                "name":      inp.get("name", ""),
                "value":     inp.get("value", ""),
                "xss_probe": itype in XSS_PROBE_TYPES or inp.name == "textarea",
            })

        result["forms"].append({
            "action":  full_action,
            "method":  method,
            "enctype": enctype,
            "fields":  fields,
        })

    # ── iFrames ──
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        result["iframes"].append({
            "src":     urljoin(base_url, src) if src else "(no src)",
            "name":    iframe.get("name", ""),
            "sandbox": iframe.get("sandbox", ""),
        })

    return result


# ─── Phase 2: XSS reflection probe ──────────────────────────────────────────

def probe_xss(page: dict, timeout: int) -> list:
    """
    For each form with XSS-prone fields, submit each payload and check reflection.
    Returns list of hit dicts.
    """
    hits = []
    base_url = page["url"]

    for form in page["forms"]:
        probe_fields = [f for f in form["fields"] if f["xss_probe"] and f["name"]]
        if not probe_fields:
            continue

        for field in probe_fields:
            for payload in XSS_PAYLOADS:
                # Build form data: fill probe field with payload, others with "test"
                data = {}
                for f in form["fields"]:
                    if not f["name"]:
                        continue
                    data[f["name"]] = payload if f["name"] == field["name"] else (f["value"] or "test")

                resp = fetch(
                    form["action"], timeout,
                    method=form["method"],
                    data=data
                )
                if resp is None:
                    continue

                if is_reflected(payload, resp.text):
                    hits.append({
                        "url":     form["action"],
                        "method":  form["method"],
                        "field":   field["name"],
                        "payload": payload,
                        "type":    field["type"],
                    })
                    break  # One confirmed hit per field is enough

    # Also check URL params on GET forms / query strings
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    for param in qs:
        for payload in XSS_PAYLOADS:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urlunparse(parsed._replace(
                query=urlencode({k: v[0] for k, v in test_qs.items()})
            ))
            resp = fetch(test_url, timeout)
            if resp and is_reflected(payload, resp.text):
                hits.append({
                    "url":     test_url,
                    "method":  "GET",
                    "field":   param,
                    "payload": payload,
                    "type":    "url-param",
                })
                break

    return hits


# ─── Worker ──────────────────────────────────────────────────────────────────

def scan_target(subdomain: str, timeout: int, do_xss: bool) -> dict:
    page = scan_page(subdomain, timeout)
    page["xss_hits"] = []
    if do_xss and not page["error"]:
        page["xss_hits"] = probe_xss(page, timeout)
    return page


# ─── Printer ─────────────────────────────────────────────────────────────────

def print_result(r: dict, verbose: bool = False, do_xss: bool = False):
    sub = r["subdomain"]

    if r["error"] == "unreachable":
        print(f"{Fore.RED}[-] {sub:<50} UNREACHABLE")
        return
    if r["error"]:
        print(f"{Fore.YELLOW}[!] {sub:<50} {r['error']}")
        return

    has_findings = r["inputs"] or r["forms"] or r["iframes"]
    xss_hits     = r.get("xss_hits", [])

    if not has_findings and not xss_hits:
        if verbose:
            print(f"{Fore.WHITE}[ ] {sub:<50} no inputs found")
        return

    print(f"\n{Fore.CYAN}{'─'*72}")
    print(f"{Fore.GREEN}[+] {sub}")
    print(f"    {Fore.WHITE}URL    : {r['url']}")
    print(f"    {Fore.WHITE}Status : {r['status']}")

    # ── XSS Hits (always first — most important) ──
    if xss_hits:
        print(f"\n  {Fore.RED}🔥 XSS REFLECTION HITS ({len(xss_hits)}) ──")
        for hit in xss_hits:
            print(f"    {Fore.RED}[VULN]  field={hit['field']!r}  method={hit['method']}  type={hit['type']}")
            print(f"            {Fore.YELLOW}URL     : {hit['url']}")
            print(f"            {Fore.YELLOW}Payload : {hit['payload']}")

    # ── Inputs ──
    if r["inputs"]:
        print(f"\n  {Fore.YELLOW}── Inputs ({len(r['inputs'])}) ──")
        for inp in r["inputs"]:
            itype = inp["type"]
            name_part = f"name={inp['name']!r}" if inp["name"] else ""
            id_part   = f"id={inp['id']!r}"     if inp["id"]   else ""
            ph_part   = f"placeholder={inp['placeholder']!r}" if inp["placeholder"] else ""
            attrs     = "  ".join(filter(None, [name_part, id_part, ph_part]))
            xss_flag  = f"  {Fore.RED}← XSS probe" if inp["xss_probe"] and do_xss else ""
            color     = Fore.RED if itype in ("password", "hidden", "file") else Fore.WHITE
            print(f"    {color}[{itype:<12}]  {attrs}{xss_flag}")

    # ── Forms ──
    if r["forms"]:
        print(f"\n  {Fore.YELLOW}── Forms ({len(r['forms'])}) ──")
        for f in r["forms"]:
            enc = f"  enctype={f['enctype']!r}" if f["enctype"] else ""
            probe_count = sum(1 for fld in f["fields"] if fld["xss_probe"])
            probe_note = f"  {Fore.RED}({probe_count} XSS-probable fields)" if probe_count and do_xss else ""
            print(f"    {Fore.MAGENTA}[{f['method']:<4}]  {f['action']}{enc}{probe_note}")

    # ── iFrames ──
    if r["iframes"]:
        print(f"\n  {Fore.YELLOW}── iFrames ({len(r['iframes'])}) ──")
        for iframe in r["iframes"]:
            sb = f"  sandbox={iframe['sandbox']!r}" if iframe["sandbox"] else ""
            print(f"    {Fore.BLUE}[iframe]  {iframe['src']}{sb}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Input Scanner + XSS Reflection Tester"
    )
    parser.add_argument("-f", "--file",    required=True, help="File with subdomains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout",       type=int, default=DEFAULT_TIMEOUT,  help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--xss",           action="store_true", help="Enable XSS reflection probing on active input points")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show subdomains with no findings")
    args = parser.parse_args()

    try:
        with open(args.file) as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    if not targets:
        print("[!] No targets in file.")
        sys.exit(1)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"\n{Fore.CYAN}[*] input_scanner.py — Bug Bounty Input Scanner")
    print(f"{Fore.CYAN}[*] Targets  : {len(targets)}")
    print(f"{Fore.CYAN}[*] Threads  : {args.threads}  |  Timeout: {args.timeout}s")
    print(f"{Fore.CYAN}[*] XSS Mode : {'ON 🔥' if args.xss else 'OFF  (use --xss to enable)'}")
    print(f"{Fore.CYAN}{'─'*72}\n")

    start       = time.time()
    found_count = 0
    xss_count   = 0
    done        = 0

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_target, t, args.timeout, args.xss): t for t in targets}
        for future in as_completed(futures):
            result = future.result()
            done += 1
            if result["inputs"] or result["forms"] or result["iframes"]:
                found_count += 1
            if result.get("xss_hits"):
                xss_count += 1
            print_result(result, verbose=args.verbose, do_xss=args.xss)
            print(f"\r{Fore.WHITE}  Progress: {done}/{len(targets)}", end="", flush=True)

    elapsed = time.time() - start
    print(f"\n\n{Fore.CYAN}{'─'*72}")
    print(f"{Fore.GREEN}[*] Done in {elapsed:.1f}s")
    print(f"{Fore.GREEN}[*] Input points found : {found_count}/{len(targets)}")
    if args.xss:
        color = Fore.RED if xss_count else Fore.WHITE
        print(f"{color}[*] XSS reflections    : {xss_count} subdomains")


if __name__ == "_main_":
    main()
