#!/usr/bin/env bash
set -euo pipefail

rustc_bin=$1
shift
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

args=()
while (($#)); do
    if [[ $1 == -C && $# -gt 1 && $2 == metadata=* ]]; then
        shift 2
        continue
    fi
    if [[ $1 == -Cmetadata=* ]]; then
        shift
        continue
    fi
    args+=("$1")
    shift
done

exec "$rustc_bin" "${args[@]}" \
    "-Cmetadata=vos-service-v2" \
    "--remap-path-prefix=$repository_root=vos-source"
