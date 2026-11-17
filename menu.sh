#!/usr/bin/env bash
# Launch locally or fetch one consistent GitHub source revision. No service changes.
set -euo pipefail
command -v python3 >/dev/null || { echo 'Install Python 3 first.' >&2; exit 1; }
if [[ "$(uname -s)" != Linux ]]; then
    echo 'Run this menu on a Linux server.' >&2; exit 1
fi
NEXTGEN_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-.}")" && pwd)"
if [[ -f "$NEXTGEN_SCRIPT_DIR/scripts/menu.py" ]]; then
    NEXTGEN_SOURCE="$NEXTGEN_SCRIPT_DIR"
else
    command -v curl >/dev/null || { echo 'Install curl first.' >&2; exit 1; }
    NEXTGEN_TMP="$(mktemp -d /tmp/nextgen-menu.XXXXXXXX)"
    cleanup() {
        case "$NEXTGEN_TMP" in /tmp/nextgen-menu.*) rm -rf -- "$NEXTGEN_TMP" ;; esac
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    echo 'Downloading the menu from sabialballa/nextgen-tunnel ...'
    NEXTGEN_COMMIT="$(curl -fsSL --connect-timeout 15 --max-time 60 \
        https://api.github.com/repos/sabialballa/nextgen-tunnel/commits/main |
        python3 -c 'import json,re,sys; s=json.load(sys.stdin)["sha"]; assert re.fullmatch("[0-9a-f]{40}",s); print(s)')"
    curl -fsSL --connect-timeout 15 --max-time 180 --max-filesize 16777216 \
        "https://github.com/sabialballa/nextgen-tunnel/archive/$NEXTGEN_COMMIT.tar.gz" \
        -o "$NEXTGEN_TMP/source.tar.gz"
    python3 - "$NEXTGEN_TMP" "$NEXTGEN_COMMIT" <<'PY'
import os,pathlib,sys,tarfile
base=pathlib.Path(sys.argv[1]);prefix='nextgen-tunnel-'+sys.argv[2];total=0
with tarfile.open(base/'source.tar.gz','r:gz') as archive:
    for count,member in enumerate(archive,1):
        parts=pathlib.PurePosixPath(member.name).parts
        if count>3000 or not parts or parts[0]!=prefix or member.name.startswith('/') or '..' in parts or '\\' in member.name or not (member.isdir() or member.isfile()):
            raise ValueError('Unsafe source archive')
        total+=member.size
        if member.size>16*1024**2 or total>64*1024**2:raise ValueError('Source exceeds size limit')
        target=base.joinpath(*parts)
        if member.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o700);continue
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with archive.extractfile(member) as src,target.open('xb') as dst:
            remaining=member.size
            while remaining:
                data=src.read(min(65536,remaining))
                if not data:raise ValueError('Truncated source member')
                dst.write(data);remaining-=len(data)
        target.chmod(0o600)
if not (base/prefix/'scripts/menu.py').is_file():raise ValueError('Menu missing from source revision')
PY
    NEXTGEN_SOURCE="$NEXTGEN_TMP/nextgen-tunnel-$NEXTGEN_COMMIT"
fi
# Keep interactive input available even when invoked as curl ... | bash.
if [[ ! -t 0 ]] && ( : </dev/tty ) 2>/dev/null; then
    python3 "$NEXTGEN_SOURCE/scripts/menu.py" "$@" </dev/tty
else
    python3 "$NEXTGEN_SOURCE/scripts/menu.py" "$@"
fi
