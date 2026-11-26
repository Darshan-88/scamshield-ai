#!/bin/sh
set -eu
# Trust only operator-verified proxy CIDRs. Never trust caller-supplied forwarded headers globally.
if [ -n "${TRUSTED_PROXY_IPS:-}" ]; then
  case "$TRUSTED_PROXY_IPS" in *\**|*0.0.0.0/0*|*::/0*) echo 'Refusing unrestricted proxy trust' >&2; exit 1;; esac
  set -- --proxy-headers --forwarded-allow-ips "$TRUSTED_PROXY_IPS"
else
  set -- --no-proxy-headers
fi
exec python -m uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-access-log --limit-concurrency 32 --timeout-keep-alive 5 "$@"
