#!/usr/bin/env bash
# LA-DQ experiment runner
# - Ensures real dirs at <MNT>/ladq_{llq,bq}
# - Runs fio (LLQ solo → mixed) and parses P50/P99 + bulk BW
# - Minimal, kernel-style comments

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <mountpoint>"
  exit 1
fi

MNT="$1"
BASE="$(basename "$MNT")"

# ensure <dir> exists and is a directory
ensure_dir() {
  local d="$1"
  if [ -e "$d" ] && [ ! -d "$d" ]; then
    echo "warn: $d exists and is not a directory → moving aside"
    mv -v -- "$d" "${d}.bak.$(date +%s)"
  fi
  mkdir -p -- "$d"
}

ensure_dir "$MNT/ladq_llq"
ensure_dir "$MNT/ladq_bq"

# drop caches
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

# LLQ-only
sed "s#__MNT__#$MNT#g" ladq_small_only.fio >._llq.fio
fio --eta=never --output-format=json --output="out_llq_${BASE}.json" ._llq.fio

# Mixed (LLQ + BQ)
sed "s#__MNT__#$MNT#g" ladq_mixed.fio >._mix.fio
fio --eta=never --output-format=json --output="out_mix_${BASE}.json" ._mix.fio

# ----- jq helpers -----
# percentile(ns): prefer sync.lat_ns → sync.clat_ns → write.clat_ns; fallback to <=target highest key
get_pct_le_ns() {
  local file="$1"
  local job="$2"
  local target="$3"
  jq -r --arg J "$job" --argjson T "$target" '
    (.jobs[]|select(.jobname==$J)|.sync.lat_ns.percentile) //
    (.jobs[]|select(.jobname==$J)|.sync.clat_ns.percentile) //
    (.jobs[]|select(.jobname==$J)|.write.clat_ns.percentile) //
    {}
    | to_entries
    | map({k:(.key|tonumber), v:.value})
    | sort_by(.k)
    | [ .[] | select(.k <= $T) ]
    | (if length>0 then (.[-1].v) else 0 end)
  ' "$file" 2>/dev/null
}

# bulk BW(B/s): sum write.io_bytes over non-sm_sync jobs / sum runtime(sec)
# bulk BW(B/s): "bulk_q"로 시작하는 잡들의 write.bw_bytes 합산
get_bulk_bw_bytes() {
  local file="$1"
  jq -r '
    [ .jobs[]
      | select(.jobname|startswith("bulk_q"))
      | (.write.bw_bytes // 0)
    ] | add // 0
  ' "$file" 2>/dev/null
}

# unit conv
ns2us() { awk -v n="$1" 'BEGIN{printf "%.2f", (n+0.0)/1000.0}'; }
b2mib() { awk -v b="$1" 'BEGIN{printf "%.1f", (b+0.0)/1048576.0}'; }

# ----- extract -----
p50_llq_ns="$(get_pct_le_ns "out_llq_${BASE}.json" sm_sync 50)"
p99_llq_ns="$(get_pct_le_ns "out_llq_${BASE}.json" sm_sync 99)"

p50_mix_ns="$(get_pct_le_ns "out_mix_${BASE}.json" sm_sync 50)"
p99_mix_ns="$(get_pct_le_ns "out_mix_${BASE}.json" sm_sync 99)"

bulk_bw_bytes="$(get_bulk_bw_bytes "out_mix_${BASE}.json")"

p50_llq_us="$(ns2us "$p50_llq_ns")"
p99_llq_us="$(ns2us "$p99_llq_ns")"
p50_mix_us="$(ns2us "$p50_mix_ns")"
p99_mix_us="$(ns2us "$p99_mix_ns")"

# safe ratio
ratio="NA"
if awk -v x="$p99_llq_us" 'BEGIN{exit (x+0.0==0)}'; then
  ratio="$(awk -v a="$p99_mix_us" -v b="$p99_llq_us" 'BEGIN{printf "%.2fx", (a+1e-7)/b}')"
fi

# ----- report -----
printf "[%s]\n" "$MNT"
printf "  sm_sync P50: %s→%s us\n" "$p50_llq_us" "$p50_mix_us"
printf "  sm_sync P99: %s→%s us  (mix/solo=%s)\n" "$p99_llq_us" "$p99_mix_us" "$ratio"
printf "  bulk_q  BW : %s MiB/s (혼합 시)\n" "$(b2mib "$bulk_bw_bytes")"
