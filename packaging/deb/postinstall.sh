#!/bin/sh
set -e

# Create the strixd service account (sysusers if available, else useradd).
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/strixd.conf >/dev/null 2>&1 || true
elif ! getent passwd strixd >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/mailstrix --no-create-home \
            --shell /usr/sbin/nologin --comment "strixd scanning daemon" strixd || true
fi

# Own the state dir.
if getent passwd strixd >/dev/null 2>&1; then
    mkdir -p /var/lib/mailstrix/rules /var/cache/mailstrix
    chown -R strixd:strixd /var/lib/mailstrix /var/cache/mailstrix
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # On an upgrade ($1 = configure <oldver>), restart the unit so the new
    # binary takes over — but only if it was already active, so a fresh install
    # stays stopped until the operator sets a token and enables it. try-restart
    # is a no-op when the unit is not running.
    if [ "$1" = configure ] && [ -n "$2" ]; then
        systemctl try-restart strixd >/dev/null 2>&1 || true
    fi
fi

# First-time install ($2 empty) prints setup hints; an upgrade stays quiet.
if [ -z "$2" ]; then
    echo "strixd installed. Fetch rules:  sudo -u strixd strixd fetch-rules -cache-dir /var/cache/mailstrix"
    echo "Set a token in /etc/mailstrix/strixd.env, then:  systemctl enable --now strixd"
fi
