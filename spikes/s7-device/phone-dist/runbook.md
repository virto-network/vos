# Session P1 on the Fairphone 6: runbook

For the coordinator, with the owner's consent and the phone on adb over
USB. Slice 7's 7.0a: the auth statement on today's AIR (19,192 steps, one
segment, Blake2s channel), as built, at the floor (no page-Merkle
boundary), and lean (the floor without BLAKE2b and its AND table: lever
1's shape), plain and under the masked-cost proxy, at the two device
candidates nearest today's AIR (blowup 2 with 86 queries, blowup 4 with
43); and the PoW grind. Nothing here is masked: the proxy pads and
commits one log size up, it does not randomize.

Two binaries, static `aarch64-unknown-linux-musl`, no files needed (the
actor's ELF and the statement's input are embedded):

- `s7-phone-seeded`: every proof's SHA-256 checked against the x86 proof
  (`"matches_x86"`); rounds 1–3 use it;
- `s7-phone-timing`: the same cells, nothing compared (the build the
  masked gates will time, masks from the OS); one round after the
  seeded rounds, to show the two builds time alike.

Their SHA-256 are in `s7-phone.sha256`; the x86 proofs' in
`x86-references.txt`. One invocation runs eight cells, five reps each,
then 64 grinds at PoW 20 and 64 at PoW 16: about 3–4 minutes on the
phone [est]. The whole session, five invocations 60 s apart with the
battery checks, about 30 minutes. Every cell was run under qemu-aarch64
from both binaries: every proof byte-identical to x86's, the built proof
verified (`runs/qemu-seeded-p1.jsonl`).

## The cells

| cell | shape | parameters | proxy | verified |
|---|---|---|---|---|
| `built/1:86:20/plain` | the kernel's chips as derived | log blowup 1, 86 queries, PoW 20 | none | yes |
| `floor/1:86:20/plain` | page-Merkle boundary out | same | none | no (a cost proxy) |
| `floor/1:86:20/masked12` | floor | same | padded to 2^12, then +1 | no |
| `lean/1:86:20/plain` | floor less BLAKE2b and its AND table | same | none | no |
| `lean/1:86:20/masked12` | lean | same | padded to 2^12, then +1 | no |
| `floor/2:43:20/plain` | floor | log blowup 2, 43 queries, PoW 20 | none | no |
| `floor/2:43:20/masked11` | floor | same | padded to 2^11, then +1 | no |
| `lean/2:43:20/masked11` | lean | same | padded to 2^11, then +1 | no |

The built shape under the proxy is left out: 4.7–7.5 GiB on x86.

## Before each round

- Battery at least 50%; the phone out of its case, flat on a table, at
  room temperature; battery saver off, any performance mode at its default
  (note it if not); apps closed; screen kept on
  (`adb shell svc power stayon usb`).
- `adb shell dumpsys battery | grep -E 'level|temperature'`: level at
  least 50, temperature below 350 (35.0 °C). If not, wait 5 minutes and
  read again; if it was charging fast, unplug the charger's fast mode.

## Run

```sh
cd spikes/s7-device/phone-dist
sha256sum -c s7-phone.sha256            # both OK
adb push s7-phone-seeded s7-phone-timing /data/local/tmp/
adb shell chmod 755 /data/local/tmp/s7-phone-seeded /data/local/tmp/s7-phone-timing
log=../../../docs/design/research/slice-7/phone-fairphone6-p1.txt
{ adb shell getprop ro.product.model; adb shell getprop ro.soc.model
  adb shell getprop ro.build.fingerprint
  adb shell 'for c in /sys/devices/system/cpu/cpu[0-9]*; do echo "$c $(cat $c/cpufreq/cpuinfo_max_freq)"; done'
  for round in 1 2 3; do
    echo "== round $round"
    adb shell dumpsys battery | grep -E 'level|temperature'
    adb shell 'cd /data/local/tmp && ./s7-phone-seeded --reps 5 2>&1'
    adb shell dumpsys battery | grep -E 'level|temperature'
    sleep 60
  done
} | tee "$log"
```

Threads are the library's automatic choice (S28: 8 on this phone). Then,
each after the battery check above and 60 s apart, appended to the same
file:

```sh
# the four big cores (CPUs 4-7, A720), 4 threads (S28's record beside it)
{ echo "== pinned f0 t4"; adb shell 'cd /data/local/tmp && taskset f0 ./s7-phone-seeded --threads 4 --reps 5 --grind 0 2>&1'; } | tee -a "$log"
sleep 60
# the timing build, once
{ echo "== timing"; adb shell 'cd /data/local/tmp && ./s7-phone-timing --reps 5 2>&1'; } | tee -a "$log"
adb shell dumpsys battery | grep -E 'level|temperature' | tee -a "$log"
```

Keep the proofs of one round for the x86 check:
`adb shell 'cd /data/local/tmp && ./s7-phone-seeded --reps 1 --grind 0 --out proofs'`,
then `adb pull /data/local/tmp/proofs`, kept beside the session's log
(`matches_x86` has compared them with x86's already; `verified` is the
phone's own check of the built proof).

If a run prints `"kind":"error"` (each cell runs in a child process), add
`--inline` and run again. `--cells LIST` runs chosen cells,
`--threads N` sets the threads, `--grind N` the grinds (0: none).

## Reading the output

Each line starting with `{` is JSON: `"kind":"device"`, `"kind":"build"`,
one `"kind":"cell"` a cell, two `"kind":"grind"` and `"kind":"done"`.

- `prove_s_median`, `prove_s_runs`: the cell's proving time, seconds;
- `peak_rss_mib`: the cell's peak memory (pin J: at most 1,024, target 768);
- `proof_bytes`: pin J's budget is 1,572,864 (1.5 MiB);
- `verified`: `true` for `built` cells, `null` for `floor` ones;
- `matches_x86`: `true` in the seeded build, `null` in the timing build;
- `grind`: `median_ms`, `p95_ms` at PoW 20 and 16 (S29's lever).

**Findings, sent as they are:** any `verified` other than `true` on a
built cell, any `matches_x86` other than `true` in the seeded build, an
error line, a temperature at 35.0 °C or above at a round's start.

**The gate numbers** are the median of the three rounds' medians, per
cell, with the 95th percentile of the fifteen runs beside it. The ARM
factor is each cell's phone median over its x86 median at 8 threads
(`slice-7-progress.md`, 7.0a).

## What to expect

x86 (Core Ultra 7 155H, glibc, `runs/x86.jsonl`, `runs/x86-lean.jsonl`),
median of 5 on four pinned P-cores; the phone at automatic threads
estimated at 2.6–3.0× that, slice 5's kit's ratio on this phone (built 5.1 s
against 1.72 s, the floor 2.2 s against 0.84 s) [est]:

| cell | x86, 4 P-cores | phone [est] | x86 peak | bytes |
|---|---|---|---|---|
| `built/1:86:20/plain` | 1.77 s | 4.6–5.3 s | 2,280 MiB | 3,538,744 |
| `floor/1:86:20/plain` | 0.63 s | 1.6–1.9 s | 815 MiB | 2,245,957 |
| `floor/1:86:20/masked12` | 1.33 s | 3.5–4.0 s | 1,596 MiB | 2,292,090 |
| `lean/1:86:20/plain` | 0.48 s | 1.3–1.5 s | 642 MiB | 948,004 |
| `lean/1:86:20/masked12` | 0.89 s | 2.3–2.7 s | 1,245 MiB | 988,651 |
| `floor/2:43:20/plain` | 0.81 s | 2.1–2.4 s | 1,251 MiB | 1,217,153 |
| `floor/2:43:20/masked11` | 1.74 s (masked0; this cell's runs spread 1.75–3.68 s under load) | 4.5–5.2 s | 2,409 MiB | 1,243,059 |
| `lean/2:43:20/masked11` | 1.18 s | 3.1–3.6 s | 1,881 MiB | 561,297 |

The grind on x86 (4 threads): PoW 20 median 40 ms, 95th percentile 48 ms;
PoW 16 5 ms and 12 ms. The phone's memory runs about 15% above glibc's
(mimalloc); the largest cell, about 2.8 GiB, fits its 7.5 GB.

Times far above 3.5× x86 usually mean throttling or the little cores:
compare the pinned round and the battery temperature.

## How it was built

`spikes/s7-device/scripts/phone.sh` (`scripts/tree.sh`'s patched copy of
the tree; `pvm-proof.patch`): the harness's `phone` feature embeds the
actor's ELF and the input; `mimalloc` is the allocator; rust-lld links,
clang and musl 1.2.5's aarch64 headers build mimalloc's C. The seeded
build carries the x86 glibc build's proof hashes for the same cells.
