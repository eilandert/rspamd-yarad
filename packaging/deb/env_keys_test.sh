#!/bin/sh
# Guard against the .deb env sample drifting from the code. Every MAILSTRIX_* key
# named in packaging/deb/strixd.env (commented or not) must be a key the daemon
# actually reads — i.e. appear as a "MAILSTRIX_..." string token in the Go sources.
# Catches renamed/stale knobs (e.g. MAILSTRIX_ADDR when the code reads MAILSTRIX_HOST).
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env="$here/strixd.env"

# All MAILSTRIX_* keys the Go code references (env reads, struct comments, flags).
known="$(grep -rhoE 'MAILSTRIX_[A-Z0-9_]+' "$root/internal" "$root/cmd" | sort -u)"

fail=0
# Keys used in the env file: left-hand side of an (optionally #-commented) NAME=…
# (MAILSTRIX_* tokens have no whitespace, so word-splitting the list is intended.)
# shellcheck disable=SC2013
for key in $(grep -oE '^#?[[:space:]]*MAILSTRIX_[A-Z0-9_]+=' "$env" \
                | sed -E 's/^#?[[:space:]]*//; s/=$//' | sort -u); do
    if printf '%s\n' "$known" | grep -qx "$key"; then
        echo "ok   - $key"
    else
        echo "FAIL - $key in strixd.env is not read by any Go source"; fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "ALL OK"
else
    echo "FAILURES"; exit 1
fi
