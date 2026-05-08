# vulnlab.dev

Intentionally vulnerable web labs for testing security tools.

The entire `vulnlab.dev` family of subdomains is **intentionally vulnerable**. Point your DAST scanners, SAST rules, and LLM-based code reviewers at it and see what they catch.

## Subdomains

| Host | Class | Status |
|---|---|---|
| `vulnlab.dev` | Landing / index | live |
| `ssrf.vulnlab.dev` | Server-Side Request Forgery | live |

## SSRF labs (`ssrf.vulnlab.dev`)

| Path | Variant | Sink |
|---|---|---|
| `/basic` | Unfiltered URL fetch | `requests.get` |
| `/blocklist` | Substring deny-list, bypassable | `urllib.request.urlopen` |
| `/allowlist` | Naive allow-list, bypassable via userinfo | `requests.get` |
| `/scheme` | Any URL scheme accepted (file, gopher, dict) | `urllib.request.urlopen` |
| `/blind` | Body discarded; OOB-only | `httpx.get` |
| `/metadata` | AWS-IMDS-themed (mock IMDS at 169.254.169.254) | `requests.get` |

Every lab page links to its own source via `/source/<lab>`.

## Stack

- Python 3 + Flask + gunicorn
- nginx as reverse proxy via unix socket
- systemd unit per app with hardening (DynamicUser, IPAddressDeny, ProtectSystem)

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
FLASK_APP=apps.ssrf.app flask run --port 5001
FLASK_APP=apps.landing.app flask run --port 5000
FLASK_APP=apps.metadata_mock.app flask run --host=127.0.0.1 --port 8169
```

For the metadata lab to behave realistically, the IMDS mock must be reachable at `169.254.169.254:80`. In production that's done via `ip addr add 169.254.169.254/32 dev lo` and the `vulnlab-metadata-mock` systemd unit binds there directly.

## Production layout

- Working tree: `/home/chs/vulnlab.dev/` (this repo)
- Virtualenv: `/home/chs/vulnlab.dev/.venv/`
- Sockets: `/run/vulnlab-{landing,ssrf}.sock`
- nginx: `/etc/nginx/sites-enabled/{vulnlab.dev,ssrf.vulnlab.dev}.conf`
- systemd: `/etc/systemd/system/vulnlab-{landing,ssrf,metadata-mock}.service`

## Scope and security.txt

See `/.well-known/security.txt`. tl;dr: the site is *meant* to be vulnerable; you don't need to report findings. Do not abuse outbound connectivity or use the labs as a pivot.
