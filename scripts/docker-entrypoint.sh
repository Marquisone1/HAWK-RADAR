#!/bin/sh
set -e

# A bind-mounted ./data is created by Docker as root, so fix ownership
# before dropping to the unprivileged app user.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /data/backups
    chown -R appuser:appuser /data
    export HOME=/app
    exec setpriv --reuid=appuser --regid=appuser --init-groups "$@"
fi

exec "$@"
