#!/usr/bin/env bash
# aXs — Omnissa Access Microservices Configure and Deployment Toolkit.
#
#   ./axs configure -c lab
#   ./axs deploy -c lab
#
# On first use it runs scripts/setup.sh once (needs internet: fetches uv, a
# Python interpreter and all dependencies). Afterwards it runs from .venv with no
# further network access required for the tool itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "$ROOT/.venv/bin/axs" ]; then
    "$ROOT/scripts/setup.sh"
fi

export PATH="$HOME/.local/bin:$PATH"
exec "$ROOT/.venv/bin/axs" "$@"
