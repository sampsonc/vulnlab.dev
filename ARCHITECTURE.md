# vulnlab.dev — architecture

The site exists to give security tools a real, public target. Every host
under `vulnlab.dev` contains intentional, exploitable vulnerabilities. This
document is the technical reference for how it's wired up.

## Goals (and explicit non-goals)

| Goal | How it's met |
|---|---|
| Realistic SAST surface | Vulnerable code is real Python with named sinks (`requests.get`, `urllib.request.urlopen`, `httpx.get`). Source is published. |
| Realistic DAST surface | Public over HTTPS; no auth; canonical endpoints (`?url=…`); standard payloads work. |
| Distinct labs per detection pattern | One blueprint per variant; bypass-of-the-week kept out of any single lab. |
| Cloud-metadata realism | Mock metadata served at `169.254.169.254:80`, not a non-standard host/port. AWS IMDSv1, GCP Compute Engine, and Azure IMDS are all served from the same address with their real-world path prefixes and required headers. |
| Safe to host | Each lab runs as a `DynamicUser` systemd service with `IPAddressDeny`/`Allow` cages so it can demonstrate SSRF without becoming a pivot to the wider internet. |

Non-goals: not a CTF, not a competition, not gated by login or flags
(those would obstruct DAST scanners). It's a *target*, not a course.

## Domain layout

```
vulnlab.dev                    → landing page (index of vuln classes)
www.vulnlab.dev                → 301 → vulnlab.dev
ssrf.vulnlab.dev               → SSRF labs
xss.vulnlab.dev   (planned)
sqli.vulnlab.dev  (planned)
…                              → one subdomain per vuln class
```

Wildcard DNS (`*.vulnlab.dev → server IP`) is set at the registrar. New
subdomains are a single nginx vhost + certbot run away.

## Process topology

```
                          ┌─── nginx ────────────────────────────┐
                          │  :80 / :443 — public                  │
                          │  routes by Host:                      │
public internet ──────────▶  vulnlab.dev      → 127.0.0.1:8081    │ (vulnlab-landing)
                          │  ssrf.vulnlab.dev → 127.0.0.1:8082    │ (vulnlab-ssrf)
                          │                                       │
                          │  :80 on 169.254.169.254 (loopback IP) │
                          │  routes everything → 127.0.0.1:8169   │ (vulnlab-metadata-mock)
                          └───────────────────────────────────────┘

                                   not exposed by nginx — only reachable
                                   from inside the SSRF lab process:

                                            127.0.0.1:8089          (vulnlab-internal)
                                            127.0.0.1:6479          (vulnlab-gopher-target, raw TCP)
                                            169.254.169.254:80      (via the loopback nginx vhost)
```

The "internal" service at `:8089` is the canonical "you shouldn't be able
to reach this" SSRF target. The metadata mock at `169.254.169.254` is the
canonical cloud-metadata target and serves three flavors (AWS at
`/latest/`, GCP at `/computeMetadata/v1/`, Azure at `/metadata/`); GCP and
Azure additionally require their provider-specific request header, matching
production behavior. The gopher target at `:6479` stands in for any
non-HTTP TCP service (Redis, memcached, SMTP, …) and replies to any bytes
with a flag — it's reached by the `gopher` lab via pycurl/libcurl. All
serve flags so successful exploitation is unambiguous.

`ssrf.vulnlab.dev` also mounts an open redirector at `/r/?to=<url>`
(`apps/ssrf/redirector.py`). It exists so the `redirect` lab is
self-contained; it also chains cleanly through `allowlist` and `blocklist`.

## Filesystem layout

```
/home/chs/vulnlab.dev/                    working tree (this repo)
├── apps/                                 Flask apps
│   ├── landing/                          vulnlab.dev
│   ├── ssrf/                             ssrf.vulnlab.dev
│   │   ├── app.py                        registers blueprints, /source/<slug>
│   │   ├── labs/                         one module per lab variant
│   │   ├── redirector.py                 open redirector mounted at /r/
│   │   └── templates/
│   ├── internal/                         the "you shouldn't reach this" service
│   ├── metadata_mock/                    mock AWS + GCP + Azure metadata
│   └── gopher_target/                    raw TCP "redis-like" target for the gopher lab
├── deploy/
│   ├── nginx/                            source-of-truth nginx vhosts
│   └── systemd/                          source-of-truth systemd units
├── .venv/                                Python venv (not in git)
└── CLAUDE.md / ARCHITECTURE.md / README.md

/etc/nginx/sites-enabled/                 live nginx vhosts (certbot edits these in place)
/etc/systemd/system/vulnlab-*.service     live systemd units
/etc/letsencrypt/live/vulnlab.dev/        TLS certs (vulnlab.dev, www, ssrf SAN)
```

`deploy/` is the source of truth. After certbot rewrites a vhost on cert
issuance, snapshot the live file back into `deploy/nginx/` and commit.

## Hardening model

Each lab runs as its own systemd unit with:

```ini
DynamicUser=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

Plus per-service network policy:

| Service | `IPAddressDeny` | `IPAddressAllow` | Why |
|---|---|---|---|
| `vulnlab-landing` | `any` | `localhost` | Static landing; never makes outbound calls. |
| `vulnlab-ssrf` | `10/8 172.16/12 192.168/16 169.254/16` | `127/8 169.254.169.254/32` | Labs must reach the internet (realism), the internal service on 127.0.0.1, and the mock IMDS — but not other private networks. |
| `vulnlab-internal` | `any` | `localhost` | Server-only; never initiates outbound. |
| `vulnlab-metadata-mock` | `any` | `localhost` | Server-only; never initiates outbound. |
| `vulnlab-gopher-target` | `any` | `localhost` | Server-only raw TCP; never initiates outbound. |

The `IPAddressAllow=169.254.169.254/32` on `vulnlab-ssrf` overrides the
broader `IPAddressDeny=169.254.0.0/16` because the /32 prefix is more
specific (systemd documents this precedence rule).

### What's deliberately *not* caged

- The SSRF labs *can* reach other services on `127.0.0.1` — including the
  host's MariaDB on 3306 and any other localhost-only daemons. This is
  realistic and intentional. If a lab tries to fetch `http://127.0.0.1:3306/`
  it'll get a `BadStatusLine` error from the SQL protocol — exactly the
  kind of fingerprint a real SSRF gives an attacker.
- Source code is public. SAST and LLM-based tools need to read it.

## How a request flows (worked example: basic SSRF)

```
attacker → curl 'https://ssrf.vulnlab.dev/basic/?url=http://127.0.0.1:8089/secret'

  1. nginx (:443) terminates TLS, matches Host: ssrf.vulnlab.dev,
     proxies to 127.0.0.1:8082, adds X-Forwarded-Proto, X-Real-IP.

  2. gunicorn (vulnlab-ssrf) routes /basic/ to apps/ssrf/labs/basic.py.

  3. The blueprint calls requests.get(url) — url is fully attacker-controlled.

  4. The vulnlab-ssrf cgroup's IPAddressAllow lets the request through to
     127.0.0.1:8089 (vulnlab-internal).

  5. vulnlab-internal returns {"flag": "VULNLAB{ssrf-reached-internal-service}"}.

  6. The blueprint renders the response body verbatim into lab.html.

  7. nginx adds X-Vulnlab: intentionally-vulnerable on the way back out.

  8. attacker sees the flag.
```

Replace step 3's URL with `http://169.254.169.254/latest/meta-data/iam/…`
and step 4 routes through nginx's loopback vhost to `vulnlab-metadata-mock`.

## TLS and certs

- One Let's Encrypt cert covers `vulnlab.dev`, `www.vulnlab.dev`, and
  `ssrf.vulnlab.dev` (multi-SAN, not a wildcard).
- Issued and renewed by `certbot --nginx`; renewal handled by the system
  `certbot.timer`.
- Adding a new subdomain (e.g., `xss.vulnlab.dev`) means re-running
  `certbot --nginx -d vulnlab.dev -d www.vulnlab.dev -d ssrf.vulnlab.dev -d xss.vulnlab.dev`
  to expand the SAN. Or issuing a separate cert per host.

## Adding a new vuln class

The mechanical process — see `CLAUDE.md` for the cookbook version.

```
1. Copy apps/ssrf/ → apps/<class>/, rewrite labs.
2. Copy deploy/systemd/vulnlab-ssrf.service → vulnlab-<class>.service,
   change port and module path.
3. Copy deploy/nginx/ssrf.vulnlab.dev.conf → <class>.vulnlab.dev.conf,
   change server_name and proxy_pass port.
4. systemctl + certbot.
5. Add to CLASSES in apps/landing/app.py, restart vulnlab-landing.
```

The threat model can shift per class: an XSS lab probably needs no
outbound at all (`IPAddressDeny=any`); an SQLi lab might need a sidecar
DB. Re-derive the cage every time.

## Things that fail predictably

| Symptom | Cause |
|---|---|
| 502 from nginx after editing a `.py` | Service didn't auto-reload. `sudo systemctl restart vulnlab-<name>`. |
| `nginx: [emerg] bind() to 169.254.169.254:80 failed` | Loopback IP not added. `sudo systemctl start vulnlab-imds-loopback`. |
| Lab returns "Network is unreachable" for a target you expected to work | The cage is blocking it. Check `systemctl show vulnlab-ssrf \| grep IPAddress`. |
| `/source/<slug>` returns 404 | Slug not in `LABS` (in `apps/ssrf/labs/__init__.py`) or source file moved outside `apps/ssrf/`. |
| Templates serve stale content | Same as the .py case — gunicorn doesn't auto-reload. Restart. |
