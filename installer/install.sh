#!/usr/bin/env bash
# IPTM - installazione fresh (nessuna regola firewall applicata)
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
exec /usr/bin/python3 -B ./installer.py "$@"
