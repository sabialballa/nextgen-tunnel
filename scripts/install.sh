#!/bin/sh
set -eu
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required' >&2; exit 1; }
exec python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/host_install.py" install "$@"
