#!/usr/bin/env bash
# The sync check of a vendored VOS verifier kit, as a consumer runs it
# (VOS's `docs/design/spaces-pallet.md` §3.1). Kept outside the kit, under
# the consumer's review (e.g. Kreivo's `scripts/vos-sync.sh`, CODEOWNERS),
# since a change to the kit could replace the kit's own script: this one
# pins VOS's canonical repository, checks that the tag the kit's `VENDOR`
# names is there, takes `vos_kit.py` from that tag and runs it.
#
#   vos-sync.sh <kit directory> [<a local VOS clone>]
#
# Without a clone it clones VOS bare, without blobs, into a scratch
# directory under $VOS_SYNC_SCRATCH (default: $TMPDIR), removed after.
# Needs bash, git and Python 3.11 or later.
set -euo pipefail

VOS_URL="https://codeberg.org/Virto/VOS.git"
SCRIPT="pvm/proof/kit/vos_kit.py"

fail() {
    echo "vos-sync: $*" >&2
    exit 1
}

[ $# -ge 1 ] && [ $# -le 2 ] || fail "usage: vos-sync.sh <kit directory> [<a local VOS clone>]"
kit=$1
[ -f "$kit/VENDOR" ] || fail "$kit has no VENDOR file"
tag=$(sed -n 's/^tag = "\(.*\)"$/\1/p' "$kit/VENDOR")
[[ "$tag" =~ ^[A-Za-z0-9._/][A-Za-z0-9._/-]*$ ]] || fail "VENDOR names no tag a kit is vendored from"

base=${VOS_SYNC_SCRATCH:-${TMPDIR:-/tmp}}
mkdir -p "$base"
scratch=$(mktemp -d "$base/vos-sync.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

if [ $# -eq 2 ]; then
    repo=$2
else
    git clone --quiet --bare --filter=blob:none -- "$VOS_URL" "$scratch/vos.git"
    repo=$scratch/vos.git
fi
GIT_NO_LAZY_FETCH=1 git -C "$repo" rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null \
    || fail "VOS holds no tag $tag"
git -C "$repo" show "refs/tags/$tag:$SCRIPT" >"$scratch/vos_kit.py" \
    || fail "VOS's tag $tag has no $SCRIPT"
python3 -I "$scratch/vos_kit.py" sync "$kit" --vos "$repo" --scratch "$scratch/work"
