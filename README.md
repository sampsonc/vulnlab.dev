# vulnlab.dev

Intentionally vulnerable web labs for testing security tools.

Live at **<https://vulnlab.dev>**. Every host under `vulnlab.dev` contains real, exploitable bugs by design — point your DAST scanners, SAST rules, and LLM-based code reviewers at it and see what each one catches.

## Subdomains

| Host | Class | Status |
|---|---|---|
| `vulnlab.dev` | Landing / index | live |
| `ssrf.vulnlab.dev` | Server-Side Request Forgery | live |
| `xss.vulnlab.dev` | Cross-Site Scripting | planned |
| `sqli.vulnlab.dev` | SQL Injection | planned |

## SSRF labs (`ssrf.vulnlab.dev`)

| Path | Variant | Sink |
|---|---|---|
| `/basic` | Unfiltered URL fetch | `requests.get` |
| `/blocklist` | Substring deny-list, bypassable (`0.0.0.0`, decimal IPs, etc.) | `urllib.request.urlopen` |
| `/allowlist` | "URL must contain `vulnlab.dev`" — bypassable via path/query | `requests.get` |
| `/scheme` | Any URL scheme accepted (`file://`, `gopher://`, …) | `urllib.request.urlopen` |
| `/blind` | Response body discarded — OOB callback required | `httpx.get` |
| `/metadata` | AWS-themed; mock IMDSv1 at `169.254.169.254` | `requests.get` |

Every lab page links to its own source via `/source/<slug>`.

## Stack

- Python 3 + Flask + gunicorn
- nginx as TLS terminator + reverse proxy
- One systemd unit per app, each with `DynamicUser=yes`, `ProtectSystem=strict`, `IPAddressDeny`/`Allow` cages
- Let's Encrypt via certbot

For the full topology and hardening details, see [`ARCHITECTURE.md`](./ARCHITECTURE.md).
For agent-facing notes (gotchas when editing), see [`CLAUDE.md`](./CLAUDE.md).

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install flask gunicorn requests httpx pygments
# Run them all on different ports:
FLASK_APP=apps.landing.app       flask run --port 5000
FLASK_APP=apps.ssrf.app          flask run --port 5001
FLASK_APP=apps.internal.app      flask run --port 8089
FLASK_APP=apps.metadata_mock.app flask run --port 8169
```

The metadata lab needs the IMDS mock reachable at `http://169.254.169.254/`
for canned IMDS payloads to work as-is. In production that's done via
`ip addr add 169.254.169.254/32 dev lo` (managed by the `vulnlab-imds-loopback`
systemd unit) and an nginx vhost that listens on that IP and proxies to the
mock service. Locally you can skip this and just point fetches at the dev
port.

## Production deploy

| Component | Path |
|---|---|
| Working tree | `/home/chs/vulnlab.dev/` |
| Virtualenv | `/home/chs/vulnlab.dev/.venv/` |
| systemd units | `/etc/systemd/system/vulnlab-*.service` |
| nginx vhosts | `/etc/nginx/sites-enabled/{vulnlab.dev,ssrf.vulnlab.dev,vulnlab-imds}.conf` |
| TLS certs | `/etc/letsencrypt/live/vulnlab.dev/` |

Source-of-truth copies of the deploy configs live in [`deploy/`](./deploy/).
After certbot rewrites the nginx vhosts on cert issuance, snapshot them back.

## Scope and security.txt

See [/.well-known/security.txt](https://vulnlab.dev/.well-known/security.txt). tl;dr: the site is *meant* to be vulnerable; you don't need to report findings against the labs themselves. Don't abuse outbound connectivity or use the labs as a pivot.

If you find a bug in the lab platform itself (something that lets a visitor
break out of the lab process, escalate beyond the documented threat model,
or affect other users), email **carl.sampson@gmail.com**.

## Built by

[Carl Sampson (chs)](https://chs.us/) — application security researcher.

vulnlab.dev sits alongside:

- **[chs.us](https://chs.us/)** — personal site with hands-on guides, including the [SSRF guide](https://chs.us/guides/ssrf/) the labs are based on.
- **[appsec.fyi](https://appsec.fyi/)** — curated AppSec reading and reference; see the [SSRF page](https://appsec.fyi/ssrf.html).
- **[outofbits.com](https://outofbits.com/)** — out-of-band application security testing service ("the OAST listener that talks back"). Useful for the blind SSRF lab.
