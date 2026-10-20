#!/usr/bin/env python3
"""
subscan - find a domain's subdomains from certificate transparency logs.

Every publicly trusted TLS certificate is logged in Certificate
Transparency, so the names on them reveal a domain's subdomains without
sending a single packet to the target. subscan pulls those names from
crt.sh and Cert Spotter, de-duplicates them, and can resolve each one
to show which are live, which share IPs, and which look forgotten.

Passive and read-only, but only investigate domains you own or are
authorized to assess.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import json
import random
import os
import re
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "1.0.0"

UA = f"subscan/{__version__} (+https://github.com/Landull/subscan)"
NAME_RE = re.compile(r"^[a-z0-9*_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")
INTERESTING = ("dev", "test", "stage", "staging", "uat", "qa", "admin", "vpn", "internal", "old",
               "legacy", "backup", "jenkins", "git", "gitlab", "jira", "confluence", "grafana",
               "kibana", "beta", "demo", "sandbox", "preprod", "debug", "remote", "rdp", "citrix",
               "owa", "autodiscover", "sso", "login", "portal", "api", "db", "sql", "ftp")


def ssl_context(verify=True):
    """Default TLS context. python.org builds for macOS ship without CA certificates,
    so when none are loaded there, borrow the system roots from the macOS keychain."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sys.platform == "darwin" and not ctx.cert_store_stats().get("x509_ca"):
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=30).stdout
            if pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError, ValueError):
            pass
    return ctx


SSL_CTX = ssl_context()


def http_json(url, timeout, retries=2):
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                return json.loads(resp.read().decode("utf-8", "replace") or "[]")
        except urllib.error.HTTPError as err:
            last = err
            if err.code not in (429, 502, 503, 504):
                break
        except (urllib.error.URLError, OSError, ValueError) as err:
            last = err
        time.sleep(2 * (attempt + 1))  # crt.sh is often busy
    raise RuntimeError(str(getattr(last, "reason", last)))


def from_crtsh(domain, timeout):
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    names = set()
    for row in http_json(url, timeout):
        for n in str(row.get("name_value", "")).splitlines():
            names.add(n)
        names.add(str(row.get("common_name", "")))
    return names


def from_certspotter(domain, timeout):
    names = set()
    after = None
    for _ in range(5):  # free tier pages; stop after a few
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        rows = http_json("https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(params), timeout)
        if not rows:
            break
        for row in rows:
            names.update(row.get("dns_names", []))
        after = rows[-1].get("id")
    return names


SOURCES = {"crtsh": from_crtsh, "certspotter": from_certspotter}


def clean(names, domain):
    out = set()
    for n in names:
        n = n.strip().lower().rstrip(".")
        if not n or " " in n or "@" in n:
            continue
        wildcard = n.startswith("*.")
        n = n[2:] if wildcard else n
        if (n == domain or n.endswith("." + domain)) and NAME_RE.match(n):
            out.add(n)
    return out


def resolve(name):
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({i[4][0] for i in infos})


def wildcard_ips(domain):
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return set(resolve(f"{label}.{domain}"))


def tag(name, domain):
    sub = name[: -len(domain)].rstrip(".")
    labels = re.split(r"[.-]", sub)
    hits = [w for w in INTERESTING if w in labels]
    return ", ".join(hits)


def parse_args(argv):
    p = argparse.ArgumentParser(prog="subscan",
                                description="Find subdomains from certificate transparency logs.")
    p.add_argument("domain", help="domain to search, e.g. example.com")
    p.add_argument("-s", "--source", choices=("all", *SOURCES), default="all",
                   help="CT source to query (default: all)")
    p.add_argument("-r", "--resolve", action="store_true", help="resolve each name and show live IPs")
    p.add_argument("-l", "--live-only", action="store_true", help="with --resolve, hide names that don't resolve")
    p.add_argument("-j", "--threads", type=int, default=20, help="parallel workers (default 20)")
    p.add_argument("-t", "--timeout", type=float, default=45, help="per-request timeout (crt.sh can be slow)")
    p.add_argument("-f", "--format", choices=("table", "txt", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    domain = re.sub(r"^\w+://", "", args.domain.strip().lower()).split("/")[0].lstrip("*.").rstrip(".")
    if "." not in domain:
        print(f"[!] '{args.domain}' doesn't look like a domain.", file=sys.stderr)
        return 2

    raw = set()
    used = []
    for name in (SOURCES if args.source == "all" else [args.source]):
        try:
            got = SOURCES[name](domain, args.timeout)
            raw |= got
            used.append(name)
            print(f"[*] {name}: {len(clean(got, domain))} names", file=sys.stderr)
        except RuntimeError as err:
            print(f"[!] {name} failed: {err}", file=sys.stderr)
    if not used:
        return 2

    names = sorted(clean(raw, domain), key=lambda n: (n.count("."), n))
    records = [{"name": n, "ips": [], "tags": tag(n, domain)} for n in names]

    wild = set()
    if args.resolve:
        wild = wildcard_ips(domain)
        if wild:
            print(f"[!] {domain} has wildcard DNS ({', '.join(sorted(wild))}); "
                  "names resolving only there are marked", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for rec, ips in zip(records, pool.map(resolve, names)):
                rec["ips"] = ips
                rec["wildcard"] = bool(ips) and set(ips) <= wild
        if args.live_only:
            records = [r for r in records if r["ips"] and not r.get("wildcard")]

    if args.format == "txt" or (args.format == "table" and args.output and args.output.endswith(".txt")):
        text = "\n".join(r["name"] for r in records)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        else:
            print(text)
    elif args.format == "table" and not args.output:
        width = max((len(r["name"]) for r in records), default=10)
        for r in records:
            line = f"  {r['name']:<{width}}"
            if args.resolve:
                ips = ", ".join(r["ips"][:3]) + (" ..." if len(r["ips"]) > 3 else "")
                line += f"  {('(wildcard) ' if r.get('wildcard') else '') + ips if r['ips'] else '-':<34}"
            if r["tags"]:
                line += f"  [{r['tags']}]"
            print(line.rstrip())
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.writer(fh)
        w.writerow(["name", "ips", "wildcard", "tags"])
        for r in records:
            w.writerow([r["name"], " ".join(r["ips"]), r.get("wildcard", ""), r["tags"]])
        if args.output:
            fh.close()
    else:
        data = json.dumps({"domain": domain, "sources": used,
                           "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "count": len(records), "subdomains": records}, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)

    live = sum(1 for r in records if r["ips"] and not r.get("wildcard"))
    msg = f"[*] {len(records)} unique name(s)" + (f", {live} resolve" if args.resolve else "")
    print(("\n" if args.format == "table" and not args.output else "") + msg, file=sys.stderr)
    if args.output:
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
