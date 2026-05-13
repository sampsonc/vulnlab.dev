#!/usr/bin/env bash
# Acceptance checks for xss.vulnlab.dev.
#
# Verifies each lab's primary exploit primitive is present in the live app,
# and that /source/<slug> and /meta/<slug> are reachable for every lab.
#
# Notes on what's actually checked:
# - "Exploit fires" here means the sink reflects the payload unescaped,
#   the CSP misconfig is observable, the sanitizer is bypassable, etc.
#   We can't run a real browser, so we check the markers that prove the
#   bug exists, not the alert(1) box.
#
# Usage:
#   ./scripts/check-xss.sh                       # checks https://xss.vulnlab.dev
#   BASE_URL=http://127.0.0.1:8083 ./scripts/check-xss.sh
#
# Exit code 0 = all pass. Nonzero = at least one regression.
set -u

BASE_URL="${BASE_URL:-https://xss.vulnlab.dev}"
CURL_OPTS=(--silent --show-error --max-time 15)

pass=0
fail=0
failures=()

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

expect_not_in_body() {
    local label="$1" url="$2" needle="$3"
    local body
    body="$(curl "${CURL_OPTS[@]}" "$url" 2>&1)" || true
    if printf '%s' "$body" | grep -qF -- "$needle"; then
        printf '  \e[31mFAIL\e[0m %s (saw forbidden %q)\n' "$label" "$needle"
        printf '       got: %s\n' "$(printf '%s' "$body" | head -c 300)"
        fail=$((fail + 1))
        failures+=("$label")
    else
        printf '  \e[32mOK\e[0m   %s\n' "$label"
        pass=$((pass + 1))
    fi
}

expect_status() {
    local label="$1" url="$2" want="$3"
    local code
    code="$(curl --silent --output /dev/null --max-time 15 --write-out '%{http_code}' "$url" || true)"
    if [[ "$code" == "$want" ]]; then
        printf '  \e[32mOK\e[0m   %s (got %s)\n' "$label" "$code"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m %s (wanted %s, got %s)\n' "$label" "$want" "$code"
        fail=$((fail + 1))
        failures+=("$label")
    fi
}

expect_header() {
    local label="$1" url="$2" needle="$3"
    local hdrs
    hdrs="$(curl --silent --output /dev/null --dump-header - --max-time 15 "$url" 2>&1)" || true
    if printf '%s' "$hdrs" | grep -qiF -- "$needle"; then
        printf '  \e[32mOK\e[0m   %s\n' "$label"
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m %s (missing %q in headers)\n' "$label" "$needle"
        printf '       got:\n%s\n' "$(printf '%s' "$hdrs" | head -c 400 | sed 's/^/         /')"
        fail=$((fail + 1))
        failures+=("$label")
    fi
}

section() { printf '\n\e[1m== %s ==\e[0m\n' "$1"; }

# --- reflected ---------------------------------------------------------------

section "Reflected XSS"

# Encode the payload via curl --get to keep the script readable.
refl_body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'q=<script>alert(1)</script>' "$BASE_URL/reflected/" 2>&1)" || true
if printf '%s' "$refl_body" | grep -qF -- '<script>alert(1)</script>'; then
    printf '  \e[32mOK\e[0m   reflected: payload echoed unescaped\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m reflected: payload escaped or missing\n'
    fail=$((fail + 1))
    failures+=("reflected reflection")
fi

# --- stored ------------------------------------------------------------------

section "Stored XSS"

# Clear first so old runs don't pollute.
curl "${CURL_OPTS[@]}" -X POST "$BASE_URL/stored/clear" -o /dev/null

marker="VULNLAB-XSS-CHECK-$$"
# Post a comment containing the marker and a payload.
curl "${CURL_OPTS[@]}" -X POST \
    --data-urlencode "author=check-script" \
    --data-urlencode "body=<img src=x onerror=alert(1)> ${marker}" \
    "$BASE_URL/stored/" -o /dev/null

stored_body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/stored/" 2>&1)" || true
if printf '%s' "$stored_body" | grep -qF -- "$marker" && \
   printf '%s' "$stored_body" | grep -qF -- 'onerror=alert(1)'; then
    printf '  \e[32mOK\e[0m   stored: comment persisted and rendered unescaped\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m stored: payload not persisted or escaped\n'
    fail=$((fail + 1))
    failures+=("stored persist+render")
fi

# Clean up so we don't leave junk in production.
curl "${CURL_OPTS[@]}" -X POST "$BASE_URL/stored/clear" -o /dev/null

# --- dom ---------------------------------------------------------------------

section "DOM XSS"

# DOM lab is pure client-side: server emits the vulnerable JS regardless of
# query. Verify the page and the vulnerable sink string are present.
dom_body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/dom/" 2>&1)" || true
if printf '%s' "$dom_body" | grep -q "innerHTML" && \
   printf '%s' "$dom_body" | grep -q "location.hash"; then
    printf '  \e[32mOK\e[0m   dom: page contains location.hash -> innerHTML sink\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m dom: vulnerable JS sink missing from page\n'
    fail=$((fail + 1))
    failures+=("dom JS sink")
fi

# --- csp-bypass --------------------------------------------------------------

section "CSP bypass (same-origin JSONP)"

expect_header "csp-bypass: CSP header present with script-src 'self'" \
    "$BASE_URL/csp-bypass/" \
    "script-src 'self'"

# The JSONP endpoint reflects ?cb=<name> into executable JS without sanitizing
# the callback name — that's the bypass primitive.
jsonp_body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/csp-bypass/jsonp?cb=alert(1)//" 2>&1)" || true
if printf '%s' "$jsonp_body" | grep -qF -- 'alert(1)//('; then
    printf '  \e[32mOK\e[0m   jsonp: cb reflected unsanitized as JS\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m jsonp: cb not reflected\n'
    printf '       got: %s\n' "$(printf '%s' "$jsonp_body" | head -c 200)"
    fail=$((fail + 1))
    failures+=("jsonp reflection")
fi

# Same-origin: csp-bypass page and jsonp endpoint must share the origin.
# (Trivially true since both come from /csp-bypass/* — but worth asserting
# in case someone moves jsonp to a separate host without realizing it kills
# the bypass.)
expect_status "jsonp endpoint reachable" "$BASE_URL/csp-bypass/jsonp?cb=foo" "200"

# --- mxss --------------------------------------------------------------------

section "mXSS (regex sanitizer + innerHTML reparse)"

# Naive payload (space-separated onerror) should be stripped by the regex.
naive="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'comment=<img src=x onerror=alert(1)>' "$BASE_URL/mxss/" 2>&1)" || true
# The sanitized-text section should NOT contain onerror=alert.
if printf '%s' "$naive" | awk '/Server-side sanitized/,/<\/pre>/' | grep -qF 'onerror='; then
    printf '  \e[31mFAIL\e[0m mxss: regex did NOT strip naive onerror (sanitizer broken?)\n'
    fail=$((fail + 1))
    failures+=("mxss naive sanitize")
else
    printf '  \e[32mOK\e[0m   mxss: naive <img onerror=...> stripped by regex\n'
    pass=$((pass + 1))
fi

# Bypass: use `/` as attribute separator (HTML5-legal, not matched by \s+).
bypass="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'comment=<img src=x/onerror=alert(1)>' "$BASE_URL/mxss/" 2>&1)" || true
if printf '%s' "$bypass" | awk '/Server-side sanitized/,/<\/pre>/' | grep -qF '/onerror=alert(1)'; then
    printf '  \e[32mOK\e[0m   mxss: / separator bypasses regex sanitizer\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m mxss: / separator did NOT bypass (sanitizer too strict?)\n'
    fail=$((fail + 1))
    failures+=("mxss bypass")
fi

# --- source + meta coverage --------------------------------------------------

section "Source + meta coverage"

SLUGS=(reflected stored dom csp-bypass mxss)
for slug in "${SLUGS[@]}"; do
    expect_status "/source/$slug" "$BASE_URL/source/$slug" "200"
done
for slug in "${SLUGS[@]}"; do
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
