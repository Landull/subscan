# subscan

A small, dependency-free tool that finds a domain's subdomains from Certificate Transparency logs, without touching the target.

- Pulls every name from **crt.sh** and **Cert Spotter** and de-duplicates them
- Completely **passive**: no packets are sent to the target's servers
- Optional **DNS resolution** to see which names are live, with **wildcard DNS detection**
- **Tags interesting names**: dev, staging, vpn, admin, jenkins, old, backup and friends
- Plain-text output for piping into other tools, plus CSV / JSON

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# Every subdomain on record
python subscan.py example.com

# Resolve them and only show live ones
python subscan.py example.com -r -l

# Plain list for piping into another tool
python subscan.py example.com -f txt > subs.txt
python ../certaudit/certaudit.py -i subs.txt   # e.g. check every cert
```

### Example output

```
$ python subscan.py example.com -r
[*] crtsh: 41 names
[*] certspotter: 37 names
  example.com                93.184.215.14
  api.example.com            93.184.215.20                       [api]
  dev-api.example.com        -                                   [dev, api]
  mail.example.com           93.184.215.31
  vpn.example.com            203.0.113.8                         [vpn]
  www.example.com            93.184.215.14
  jenkins.old.example.com    -                                   [old, jenkins]
  staging.app.example.com    198.51.100.44                       [staging]

[*] 43 unique name(s), 6 resolve
```

## Options

| Flag | Description |
|---|---|
| `-s, --source` | CT source to query (default: all) (`all` / `crtsh` / `certspotter`) |
| `-r, --resolve` | Resolve each name and show live IPs |
| `-l, --live-only` | With --resolve, hide names that don't resolve |
| `-j, --threads N` | Parallel workers (default 20) |
| `-t, --timeout N` | Per-request timeout (crt.sh can be slow) |
| `-f, --format` | Output format (`table` / `txt` / `csv` / `json`) |
| `-o, --output FILE` | Write results to a file |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Search finished |
| `2` | Bad domain, or every source failed |

## Notes

Certificate Transparency only shows names that have had a public TLS certificate. Internal-only names, and names covered by a wildcard certificate, won't appear.

Names that show up but don't resolve are worth a look: they're often retired systems whose DNS was removed, or still exist on an internal resolver.

crt.sh is a free community service and is often slow or busy; subscan retries a few times and uses a generous timeout. If it keeps failing, use `-s certspotter`.

The search itself is passive, but only run it against systems and networks you own or have written permission to test. Scanning other people's networks can be illegal even when nothing is broken.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s scankit.
