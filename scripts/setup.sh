#!/usr/bin/env bash
# One-time setup -- run once on the target host WITH internet. Fetches
# everything the toolkit needs and leaves a ready-to-use .venv:
#
#   1. uv        -- the installer/runtime (fetched if not already present)
#   2. Python    -- uv downloads a suitable interpreter (no system Python needed)
#   3. all deps  -- installed into .venv from PyPI
#
# After this, `./ws1access ...` runs offline from the local .venv.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

have() { command -v "$1" >/dev/null 2>&1; }

# 1. uv -- fetch it if the host does not have it (needs internet, once).
if ! have uv && [ ! -x "$HOME/.local/bin/uv" ]; then
    echo ">> fetching uv ..."
    if have brew; then
        brew install uv
    else
        curl -LsSf https://astral.sh/uv/install.sh | sh
    fi
fi
export PATH="$HOME/.local/bin:$PATH"
echo ">> uv $(uv --version | awk '{print $2}')"

# 2. + 3. Python + all deps + the project itself, into .venv.
#    uv reads pyproject.toml: it downloads an interpreter matching requires-python
#    and installs every dependency -- no pre-installed Python required.
echo ">> uv sync (Python + dependencies) ..."
uv sync --project "$ROOT"

echo ">> ready. Run: ./ws1access configure   (or deploy/status/validate)"
