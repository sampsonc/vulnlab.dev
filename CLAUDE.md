# vulnlab.dev — agent notes

Intentionally vulnerable web labs for testing security tools. Each vuln class
gets its own subdomain. Currently `ssrf.vulnlab.dev` and `xss.vulnlab.dev`
are live; the shape extends to `sqli.`, `ssti.`, etc.

## Topology

| Service | Bind | Backed by |
|---|---|---|
| nginx | `:80` / `:443` (vulnlab.dev, ssrf.vulnlab.dev, xss.vulnlab.dev) | system nginx |
| nginx | `169.254.169.254:80` (mock IMDS proxy) | system nginx |
| `vulnlab-landing` | `127.0.0.1:8081` | gunicorn → `apps.landing.app:app` |
| `vulnlab-ssrf` | `127.0.0.1:8082` | gunicorn → `apps.ssrf.app:app` |
| `vulnlab-xss` | `127.0.0.1:8083` | gunicorn → `apps.xss.app:app` |
| `vulnlab-internal` | `127.0.0.1:8089` | gunicorn → `apps.internal.app:app` (the SSRF labs' "you shouldn't reach this" target) |
| `vulnlab-metadata-mock` | `127.0.0.1:8169` | gunicorn → `apps.metadata_mock.app:app` (AWS + GCP + Azure flavors, all on 169.254.169.254 via nginx) |
| `vulnlab-gopher-target` | `127.0.0.1:6479` | python → `apps.gopher_target.app` (raw TCP, replies to any bytes with a flag; used by the gopher SSRF lab) |
| `vulnlab-imds-loopback` | oneshot | adds `169.254.169.254/32` to `lo` |

Nothing on `:8089`, `:8169`, or `:6479` is exposed by nginx — they're only
reachable from the lab process itself, which is the point.

The SSRF app also mounts an open redirector at `/r/?to=<url>` on
`ssrf.vulnlab.dev` (see `apps/ssrf/redirector.py`). It exists so the
`redirect` lab is self-contained; it is also useful for chaining through
`allowlist` and `blocklist`.

## Gotchas

- **Templates and Python code are not auto-reloaded.** After editing anything
  under `apps/`, `sudo systemctl restart vulnlab-<name>` is required for the
  change to be visible.
- **Do not add CSP, X-Frame-Options, or other defensive headers to the SSRF
  nginx vhost.** Several labs reflect HTML or fetch attacker URLs; security
  headers would mask the very behavior tools are supposed to detect.
- **The SSRF service's network cage is load-bearing.** It uses
  `IPAddressDeny=10/8 172.16/12 192.168/16 169.254/16` plus
  `IPAddressAllow=127/8 169.254.169.254/32`. The /32 allow takes precedence
  over the /16 deny for the IMDS address. If you ever change these, verify
  with `curl 'https://ssrf.vulnlab.dev/basic/?url=http://10.10.10.10'` (must
  fail) and `…/?url=http://169.254.169.254/latest/meta-data/instance-id`
  (must succeed).
- **Repo configs vs live configs.** `deploy/nginx/` and `deploy/systemd/`
  are the source of truth. After running `certbot --nginx`, certbot rewrites
  `/etc/nginx/sites-enabled/*.conf` to add 443 blocks — snapshot those back
  into `deploy/nginx/` and commit, so the repo stays canonical.
- **Two SSRF lab variants intentionally use weak validators that look
  "almost right" (`blocklist`, `allowlist`).** Don't "fix" them — the bypass
  *is* the lab.

## Adding a new vuln class subdomain

Pattern is mechanical. Repeat what `ssrf` did:

1. New Flask app at `apps/<class>/` with `app.py` + `templates/` + `labs/`.
2. New systemd unit at `deploy/systemd/vulnlab-<class>.service` (copy
   `vulnlab-ssrf.service`, change port and module path; revisit
   `IPAddressDeny`/`Allow` for the threat model — XSS labs probably don't
   need outbound at all).
3. New nginx vhost at `deploy/nginx/<class>.vulnlab.dev.conf` (copy
   `ssrf.vulnlab.dev.conf`, change `server_name` and `proxy_pass` port).
4. `sudo certbot --nginx -d <class>.vulnlab.dev`.
5. Add the class to `CLASSES` in `apps/landing/app.py` and restart
   `vulnlab-landing`.

## Verifying a lab "works"

A lab passes acceptance when:
1. The intended exploit returns the lab's flag/marker.
2. The intended *non-exploit* (the validator's happy path) is rejected or
   safely handled.
3. `curl /source/<slug>` returns syntax-highlighted source.
4. `curl /meta/<slug>` returns the lab's detection hint JSON (CWE, subtype,
   exploit examples, success markers, tags) for scanner benchmarking.

The SSRF canonical exploits below are encoded in `scripts/check-ssrf.sh`
(run after every deploy; nonzero exit on regression).

For SSRF specifically, the canonical exploit targets are:
- `http://127.0.0.1:8089/secret` → returns `VULNLAB{ssrf-reached-internal-service}`
- `http://127.0.0.1:8089/webhook-callback` → response header `X-Internal-Flag: VULNLAB{ssrf-webhook-leaked-via-headers}` (used by `webhook` lab)
- `gopher://127.0.0.1:6479/_anything` (via pycurl/libcurl) → returns `+VULNLAB{ssrf-gopher-pivot-to-redis-like-service}` (used by `gopher` lab)
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnlab-imds-test-role` → mock AWS creds (`AKIAIOSFODNN7EXAMPLE`)
- `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google` → mock GCP OAuth token (used by `metadata-gcp`)
- `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with `Metadata: true` → mock Azure MSI token (used by `metadata-azure`)

## What's deliberately *not* hardened

- The labs *can* reach `127.0.0.1:3306` (the host's MariaDB). This is by
  design — SSRF realistically pivots to local services. If that ever
  becomes a problem, the fix is per-service network namespacing, not
  tightening `IPAddressAllow`.
- Source code is public on purpose. SAST and LLM tools need to read it.

## Reference material the labs are based on

- https://chs.us/guides/ssrf/
- https://appsec.fyi/ssrf.html
