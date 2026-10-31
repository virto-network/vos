"""The CPU split's cell and time model (slice 7, step 7.18's exploration).

Inputs, all in `runs/`: the CPU's AIR by constraint function and every
opcode's flags (`cpu-family-usage.json`, from `dump.patch`'s test), the
traced kernels' opcode mixes and the segment AIR's natural log sizes per
window (`mix.jsonl`, from `dump.patch`'s kernel-test hook), and the
measured device and phone runs quoted below. `python3 model.py` prints the
tables `docs/design/research/slice-7/7.18-cell-model.md` quotes
(`runs/model-out.txt`).

The data again, from the repository's root: `git apply
spikes/s7-split/dump.patch` (a test in the CPU chip's module and a hook in
the kernel suite's `traced`, neither committed), the test actors built
(`just build-test-actors`), then

    CPU_FAMILY_JSON=$PWD/spikes/s7-split/runs/cpu-family-usage.json \
      cargo test -p vos-pvm-proof --lib dump_family_usage
    S7_MIX=$PWD/spikes/s7-split/runs/mix.jsonl cargo test --release \
      -p vos-pvm-proof --test kernel -- --test-threads=2 \
      device_kernel::a_device_kernels_shape window_kernel::the_window_settles \
      balance::a_balance_is_stated reads::

(`S7_MIX` appends: remove the file first.)
"""

import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cpu_families import Cpu  # noqa: E402
import leaf  # noqa: E402

cpu = Cpu()

# ---------------------------------------------------------------------------
# Families.

MEMORY_FLAGS = {"IsLoad", "IsMemSize1", "IsMemSize2", "IsMemSize4", "IsMemSize8"}
CONTROL_FLAGS = {"IsJump", "IsJumpInd", "IsLoadImmJumpInd", "IsTrap"}
# The ALU's rarer half: division and remainder (the logical right shifts go
# through DivRem too, so they stay in the core), the bit counts, the byte
# manipulations, min/max, conditional moves, signed MulUpper.
ALU_EXT_FLAGS = {"IsCountSetBits", "IsLzb", "IsTzb", "IsReverseBytes", "IsZeroExt16",
                 "IsSignExt8", "IsSignExt16", "IsMinS", "IsMinU", "IsMaxS", "IsMaxU",
                 "IsCmovIz", "IsCmovNz", "IsMulUpperSU", "IsMulUpperSS", "IsDivS"}


def family(op):
    """An opcode's family: host calls, control flow, memory, the ALU."""
    if op.startswith("Ecalli"):
        return "host"
    flags = set(cpu.opcodes[op])
    if (op in ("Fallthrough", "Unlikely", "Trap") or flags & CONTROL_FLAGS
            or any(f.startswith("IsBr") for f in flags)):
        return "control"
    if flags & MEMORY_FLAGS:
        return "memory"
    if flags & ALU_EXT_FLAGS or (op.startswith(("Div", "Rem"))):
        return "alu_ext"
    return "alu"


ALL_OPS = sorted(cpu.opcodes)

# A variant: its components, each a set of families.
VARIANTS = {
    "today": [{"alu", "alu_ext", "memory", "control", "host"}],
    "host out": [{"host"}, {"alu", "alu_ext", "memory", "control"}],
    "2-way (ALU | rest)": [{"alu", "alu_ext"}, {"memory", "control", "host"}],
    "3-way (ALU | memory | control+host)": [{"alu", "alu_ext"}, {"memory"},
                                            {"control", "host"}],
    "4-way (ALU | memory | control | host)": [{"alu", "alu_ext"}, {"memory"}, {"control"},
                                              {"host"}],
    "5-way (ALU core | ALU rare | memory | control | host)": [
        {"alu"}, {"alu_ext"}, {"memory"}, {"control"}, {"host"}],
}

_reduced = {}


def component(families, code_ops=None, calls=(1024, 1025, 1026)):
    """A component holding `families`' opcodes (those of `code_ops` alone when
    given: a per-program CPU): its main columns, relation entries and
    constraints, or None when no opcode is left."""
    ops = [op for op in ALL_OPS if family(op) in families]
    if code_ops is not None:
        ops = [op for op in ops if op in code_ops or (op == "Ecalli" and "Ecalli" in code_ops)]
    if not ops:
        return None
    calls = tuple(calls) if "host" in families else ()
    key = (tuple(ops), calls)
    if key not in _reduced:
        r = cpu.reduce(ops, calls)
        _reduced[key] = {"main": len(r["main"]), "fractions": r["fractions"],
                         "constraints": r["constraints"], "relations": r["relations"],
                         "ops": ops}
    return _reduced[key]


def interaction(fractions):
    """Interaction columns: a QM31 (four) a pair of fractions."""
    return 4 * math.ceil(fractions / 2)


# Today's CPUs, exactly: format 35's (580 main, 96 fractions) and the shared
# set's (formats 41 and 45: 581 main, 99 fractions; 4 blinding columns
# masked).
TODAY = {"main35": 580, "inter35": 192, "main41": 581, "inter41": 200, "constraints35": 815,
         "constraints41": 826}


def log2ceil(n):
    return max(0, math.ceil(math.log2(max(n, 1))))


# ---------------------------------------------------------------------------
# Kernels and their mixes.

def load_mix():
    windows, code = {}, {}
    for line in open(os.path.join(HERE, "runs", "mix.jsonl")):
        d = json.loads(line)
        if d["window"] == "code":
            code[d["kernel"]] = d["code"]
            continue
        windows[(d["kernel"], d["window"], d["from"])] = d
    return windows, code


WINDOWS, CODE = load_mix()


def family_rows(mix):
    rows = {}
    for op, n in mix.items():
        f = family(op.split(":")[0])
        rows[f] = rows.get(f, 0) + n
    return rows


def calls_of(mix):
    return sorted(int(op.split(":")[1]) for op in mix if op.startswith("Ecalli:"))


# ---------------------------------------------------------------------------
# The device shape (format 45, h = 256): the auth kernel's chips as measured
# (`spikes/s7-device/runs/x86-h256.jsonl`), columns each (main, interaction,
# preprocessed and the masking's blinding), each committed at twice its rows.

DEVICE_CHIPS = ["CPU", "POSEIDON2", "MEMORY", "DEVICE_MEMORY", "DATA_TABLE", "REGISTER_MEMORY",
                "DEVICE_BOUNDARY", "DEVICE_IO", "PROGRAM_MEMORY", "JUMP_TABLE", "WITNESS_INPUT",
                "RANGE_MULTIPLICITY_256", "BITWISE_LOOKUP", "POWER_OF_TWO", "BYTE_TO_BITS", "MUL",
                "BITWISE", "COMPARE", "DIVREM"]
DEVICE_COLUMNS = [785, 1063, 62, 112, 14, 67, 45, 18, 47, 18, 42, 10, 12, 18, 18, 298, 103, 58,
                  413]
AUTH_LOGS_45 = [11, 10, 14, 11, 13, 12, 10, 10, 13, 10, 11, 10, 10, 10, 10, 10, 10, 10, 10]
DEVICE_FLOOR = 10
# The segment AIR's chip order (`chip_idx`), for the node's natural sizes.
SEGMENT = [c["name"] for c in leaf.CHIPS]


def device_logs(window):
    """A device kernel's chip log sizes from its run: the segment AIR's
    natural sizes where the chip is shared, the device chips from the run's
    bytes (the ledger a row an access and two a byte first touched and
    closed, the boundary a row a byte; checked against the auth kernel's
    measured sizes), each at least the floor."""
    nat = dict(zip(SEGMENT, window["log_sizes"]))
    steps = window["to"] - window["from"]
    accesses = window["mem_bytes"] + window["witness_bytes"] + 2 * window["distinct"]
    logs = {
        "CPU": log2ceil(steps),
        "POSEIDON2": DEVICE_FLOOR,
        "MEMORY": log2ceil(accesses),
        "DEVICE_MEMORY": log2ceil(window["distinct"]),
        "DATA_TABLE": 13,
        "REGISTER_MEMORY": nat["REGISTER_MEMORY"],
        "DEVICE_BOUNDARY": DEVICE_FLOOR,
        "DEVICE_IO": DEVICE_FLOOR,
        "PROGRAM_MEMORY": nat["PROGRAM_MEMORY"],
        "JUMP_TABLE": nat["JUMP_TABLE"],
        "WITNESS_INPUT": nat["WITNESS_INPUT"],
        "MUL": nat["MUL"],
        "BITWISE": nat["BITWISE"],
        "COMPARE": nat["COMPARE"],
        "DIVREM": nat["DIVREM"],
    }
    return [max(DEVICE_FLOOR, logs.get(chip, DEVICE_FLOOR)) for chip in DEVICE_CHIPS]


def device_cells(logs, cpu_components=None):
    """Committed cells: each chip's columns at twice its rows. With
    `cpu_components` [(columns, log)], those replace the CPU."""
    cells = {}
    for chip, cols, log in zip(DEVICE_CHIPS, DEVICE_COLUMNS, logs):
        cells[chip] = cols * (2 << log)
    if cpu_components is not None:
        cells["CPU"] = sum(cols * (2 << log) for cols, log in cpu_components)
    return cells


def split_components(variant, rows, code_ops=None, calls=(1024, 1025, 1026), masked=True,
                     floor=DEVICE_FLOOR, steps=None):
    """A variant's CPU components for a run of `rows` by family: (columns,
    log, constraints, rows, component) each."""
    out = []
    for families in VARIANTS[variant]:
        comp = component(families, code_ops, calls)
        if comp is None:
            continue
        n = sum(rows.get(f, 0) for f in families)
        if variant == "today":
            main = comp["main"] if code_ops is not None else TODAY["main41"]
            fr = comp["fractions"] if code_ops is not None else 99
            cons = comp["constraints"] if code_ops is not None else 776
        else:
            main, fr, cons = comp["main"], comp["fractions"], comp["constraints"]
        cols = main + interaction(fr) + (4 if masked else 0)
        n = steps if (variant == "today" and steps is not None) else n
        log = max(floor, log2ceil(n))
        out.append((cols, log, cons + math.ceil(fr / 2), n, comp))
    return out


# ---------------------------------------------------------------------------
# Time: phone (Fairphone 6, `Threads::Auto`, the four big cores) and x86 (4
# P-cores) against committed cells [measured]. The phone: P6's three cells
# (rounds' medians) and P5's BLAKE2b-statement kernel; x86: 7.17c's one
# session (the base, the lean kernel, h = 256).

PHONE = [(11.6736, 607, 555), (15.9212, 741, 636), (19.6854, 952, 686), (44.9, 2430, 1790)]
X86 = [(11.6736, 328), (15.9212, 403), (19.6854, 472)]


def fit(points):
    n = len(points)
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    b = sum((p[0] - mx) * (p[1] - my) for p in points) / sum((p[0] - mx) ** 2 for p in points)
    return my - b * mx, b


PHONE_FIT = fit([(c, t) for c, t, _ in PHONE])
PHONE_RSS_FIT = fit([(c, r) for c, _, r in PHONE])
PHONE_PER_CELL = sum(t for _, t, _ in PHONE) / sum(c for c, _, _ in PHONE)
X86_FIT = fit(X86)


def phone_ms(mcells):
    """Two readings: the affine fit, and time proportional to cells."""
    a, b = PHONE_FIT
    return a + b * mcells, PHONE_PER_CELL * mcells


def phone_rss(mcells):
    a, b = PHONE_RSS_FIT
    return a + b * mcells


# ---------------------------------------------------------------------------
# Reports.

def fmt_m(x):
    return f"{x / 1e6:.2f}M"


def table_widths():
    print("## Columns by component (the full ISA)\n")
    print("| variant | component | opcodes | main | fractions | interaction | constraints |"
          " device columns (with 4 blinding) |")
    print("|---|---|---|---|---|---|---|---|")
    for variant, comps in VARIANTS.items():
        total = 0
        for families in comps:
            comp = component(families)
            if variant == "today":
                main, fr, cons = TODAY["main41"], 99, 776
            else:
                main, fr, cons = comp["main"], comp["fractions"], comp["constraints"]
            cols = main + interaction(fr) + 4
            total += cols
            print(f"| {variant} | {'+'.join(sorted(families))} | {len(comp['ops'])} | {main} |"
                  f" {fr} | {interaction(fr)} | {cons} | {cols} |")
        print(f"| {variant} | **sum** | | | | | | **{total}** |")
    r = cpu.reduce(ALL_OPS)
    print(f"\nThe full ISA reduced as one component keeps {len(r['main'])} of today's 581 main"
          f" columns: {cpu.column_names(set(range(cpu.n_main)) - set(r['main']))} are pinned"
          " to zero or read by nothing.\n")


def table_auth():
    print("## The auth device kernel (format 45)\n")
    w = WINDOWS[("device/auth", "whole", 0)]
    rows = family_rows(w["mix"])
    calls = calls_of(w["mix"])
    code_ops = set(CODE["device/auth"])
    logs = device_logs(w)
    assert logs == AUTH_LOGS_45, (logs, AUTH_LOGS_45)
    print(f"Steps {w['to']}: by family {rows}; host calls {calls}. The modelled device log"
          " sizes equal the measured ones (format 45).\n")
    report_device("auth (1,722 steps)", logs, rows, code_ops, calls, steps=w["to"],
                  anchor=(607, 555))


RESULTS = []


def report_device(name, logs, rows, code_ops, calls, steps, anchor=None):
    """With `anchor`, today's shape's measured phone time (ms) and peak (MiB):
    each variant's time that times its cells' ratio (proportional) or the
    affine fit's ratio, its peak that times the peak fit's ratio."""
    before = device_cells(logs)
    total_before = sum(before.values())
    print(f"| {name} | variant | CPU components (columns × 2^log) | CPU cells | total cells |"
          " Δ total | phone ms (affine / ∝ cells) | peak MiB |")
    print("|---|---|---|---|---|---|---|---|")
    for pruned in (False, True):
        for variant in VARIANTS:
            comps = split_components(variant, rows, code_ops if pruned else None, calls,
                                     steps=steps)
            cells = device_cells(logs, [(c, l) for c, l, *_ in comps])
            total = sum(cells.values())
            desc = " + ".join(f"{c}×2^{l}" for c, l, *_ in comps)
            label = variant + (", per program" if pruned else "")
            t_aff, t_prop = phone_ms(total / 1e6)
            rss = phone_rss(total / 1e6)
            if anchor is not None:
                a0, _ = phone_ms(total_before / 1e6)
                t_aff = anchor[0] * t_aff / a0
                t_prop = anchor[0] * total / total_before
                rss = anchor[1] * rss / phone_rss(total_before / 1e6)
            RESULTS.append((name, label, total_before, total, t_aff, t_prop))
            print(f"| | {label} | {desc} | {fmt_m(cells['CPU'])} | {fmt_m(total)} |"
                  f" {100 * (total / total_before - 1):+.1f}% | {t_aff:.0f} / {t_prop:.0f} |"
                  f" {rss:.0f} |")
    print()


def table_heavy():
    print("## Heavier device kernels (node kernels' runs under the device shape)\n")
    picks = [("balance/21733", "prefix14", 0), ("window/52178", "prefix14", 0),
             ("accounts/35465", "prefix14", 0), ("accounts/150785", "prefix16", 0),
             ("accounts/248914", "prefix16", 0)]
    for kernel, kind, start in picks:
        w = WINDOWS[(kernel, kind, start)]
        steps = w["to"] - w["from"]
        rows = family_rows(w["mix"])
        logs = device_logs(w)
        calls = [c for c in calls_of(w["mix"]) if c != 1024] + [1026]
        code_ops = set(CODE[kernel])
        print(f"{kernel}, its first {steps} steps: by family {rows}; device log sizes"
              f" {dict(zip(DEVICE_CHIPS, logs))}\n")
        report_device(f"{kernel.split('/')[0]} ({steps} steps)", logs, rows, code_ops, calls,
                      steps=steps)


def table_histogram():
    print("## Opcode-family histograms\n")
    print("| kernel | window | steps | alu | alu_ext | memory | control | host |")
    print("|---|---|---|---|---|---|---|---|")
    for (kernel, kind, start), w in sorted(WINDOWS.items()):
        if kind not in ("whole", "prefix14", "prefix16"):
            continue
        if kind == "whole" and w["to"] > 1 << 16:
            pass
        steps = w["to"] - w["from"]
        rows = family_rows(w["mix"])
        cells = " | ".join(f"{100 * rows.get(f, 0) / steps:.1f}%"
                           for f in ("alu", "alu_ext", "memory", "control", "host"))
        print(f"| {kernel} | {kind} | {steps} | {cells} |")
    print()


def crossover():
    print("## The crossover: the CPU's cells against today's, by steps\n")
    print("Each split's CPU cells against today's single CPU (785 columns at twice its"
          " padded rows), the components each padded to a power of two at the 2^10 floor."
          " Two points an octave (just past a power of two, and at it), and the mean over"
          " 64 log-spaced lengths in the octave `(2^(k-1), 2^k]`.\n")
    mixes = {"auth": ("device/auth", family_rows(WINDOWS[("device/auth", "whole", 0)]["mix"])),
             "node kernels": ("accounts/248914",
                              family_rows(WINDOWS[("accounts/248914", "prefix16", 0)]["mix"]))}
    variants = [(v, False) for v in VARIANTS if v != "today"] + [
        ("today", True), ("2-way (ALU | rest)", True),
        ("4-way (ALU | memory | control | host)", True)]
    for name, (kernel, mix) in mixes.items():
        code_ops = set(CODE[kernel])
        calls = (1025, 1026) if kernel.startswith("device") else (1024, 1025)
        total = sum(mix.values())
        share = {f: n / total for f, n in mix.items()}
        print(f"### the {name} mix: {', '.join(f'{f} {100 * s:.1f}%' for f, s in share.items())}\n")
        heads = [v.split(" (")[0] + (", per program" if p else "") for v, p in variants]
        print("| steps | today's CPU cells | " + " | ".join(heads) + " |")
        print("|---|---|" + "---|" * len(variants))

        def delta(steps, variant, pruned):
            rows = {f: share[f] * steps for f in share}
            base = 785 * (2 << max(DEVICE_FLOOR, log2ceil(steps)))
            comps = split_components(variant, rows, code_ops if pruned else None, calls,
                                     steps=steps)
            return sum(c * (2 << l) for c, l, *_ in comps) / base - 1

        for log in range(10, 18):
            for steps in ((1 << (log - 1)) + 1, 1 << log):
                if log == 10 and steps != 1 << log:
                    continue
                base = 785 * (2 << max(DEVICE_FLOOR, log2ceil(steps)))
                line = [f"{100 * delta(steps, v, p):+.0f}%" for v, p in variants]
                print(f"| {steps} | {fmt_m(base)} | " + " | ".join(line) + " |")
            grid = [round(2 ** (log - 1 + (i + 1) / 64)) for i in range(64)]
            line = [f"**{100 * sum(delta(n, v, p) for n in grid) / len(grid):+.0f}%**"
                    for v, p in variants]
            print(f"| mean over (2^{log - 1}, 2^{log}] | | " + " | ".join(line) + " |")
        print()


def word_memory(window):
    """Word-level memory (7.19) [model]: the ledger a row an access (not a
    byte) and two a word first touched and closed, the boundary a row a
    word; an 8-byte word, the distinct words between distinct bytes / 8 and
    / 4 (partly touched words)."""
    accesses = 0
    for op, n in window["mix"].items():
        if op.startswith(("Load", "Store")) and not op.startswith("LoadImm"):
            accesses += n
    witness_words = window["witness_bytes"] / 8
    out = []
    for per_word in (8, 4):
        words = window["distinct"] / per_word
        out.append((log2ceil(accesses + witness_words + 2 * words), log2ceil(words)))
    return accesses, out


def levers():
    print("## Alternatives beside the split [model]\n")
    print("| kernel | today | per-program CPU | word-level memory (7.19) | right shifts through"
          " MUL (DIVREM out) | per-program CPU + word memory |")
    print("|---|---|---|---|---|---|")
    picks = [("device/auth", "whole"), ("accounts/248914", "prefix12"),
             ("accounts/248914", "prefix13"), ("balance/21733", "prefix14"),
             ("window/52178", "prefix14"), ("accounts/248914", "prefix16")]
    for kernel, kind in picks:
        w = WINDOWS[(kernel, kind, 0)]
        steps = w["to"] - w["from"]
        logs = device_logs(w)
        base = sum(device_cells(logs).values())
        code_ops = set(CODE[kernel])
        rows = family_rows(w["mix"])
        calls = (1025, 1026)
        pruned = split_components("today", rows, code_ops, calls, steps=steps)
        c_pruned = sum(device_cells(logs, [(c, l) for c, l, *_ in pruned]).values())
        accesses, wm = word_memory(w)
        wm_cells = []
        for mem_log, dm_log in wm:
            l2 = list(logs)
            l2[DEVICE_CHIPS.index("MEMORY")] = max(DEVICE_FLOOR, mem_log)
            l2[DEVICE_CHIPS.index("DEVICE_MEMORY")] = max(DEVICE_FLOOR, dm_log)
            cells = device_cells(l2)
            # The word-wide ledger: the value a word, not a byte (+7 columns).
            cells["MEMORY"] = (DEVICE_COLUMNS[2] + 7) * (2 << l2[2])
            wm_cells.append(sum(cells.values()))
        no_divrem = base - device_cells(logs)["DIVREM"]
        both = [c - base + c_pruned for c in wm_cells]
        rng = lambda xs: f"{min(xs) / 1e6:.2f}–{max(xs) / 1e6:.2f}M ({100 * (max(xs) / base - 1):+.0f}…{100 * (min(xs) / base - 1):+.0f}%)"
        print(f"| {kernel.split('/')[0]} ({steps} steps, {accesses} accesses) | {fmt_m(base)} |"
              f" {fmt_m(c_pruned)} ({100 * (c_pruned / base - 1):+.0f}%) | {rng(wm_cells)} |"
              f" {fmt_m(no_divrem)} ({100 * (no_divrem / base - 1):+.0f}%) | {rng(both)} |")
    print()


def budgets():
    print("## Device kernels by length: cells, phone time and peak [model]\n")
    print("Node kernels' runs taken as device kernels (their first 2^k steps), today and"
          " with the per-program CPU and the 4-way split per program; the phone from the"
          " fits (affine / proportional), the peak from its fit.\n")
    print("| kernel | steps | variant | cells | phone ms | peak MiB |")
    print("|---|---|---|---|---|---|")
    for kernel in ("accounts/248914", "window/52178"):
        for kind in ("prefix12", "prefix13", "prefix14", "prefix15", "prefix16"):
            w = WINDOWS.get((kernel, kind, 0))
            if w is None:
                continue
            steps = w["to"] - w["from"]
            if kind != "prefix12" and steps < 1 << (int(kind[-2:]) - 1) + 1:
                continue
            logs = device_logs(w)
            rows = family_rows(w["mix"])
            code_ops = set(CODE[kernel])
            for label, variant, pruned in (("today", "today", False),
                                           ("per-program CPU", "today", True),
                                           ("4-way per program", "4-way (ALU | memory | control | host)", True)):
                comps = split_components(variant, rows, code_ops if pruned else None, (1025, 1026),
                                         steps=steps)
                total = sum(device_cells(logs, [(c, l) for c, l, *_ in comps]).values())
                t_aff, t_prop = phone_ms(total / 1e6)
                print(f"| {kernel.split('/')[0]} | {steps} | {label} | {fmt_m(total)} |"
                      f" {t_aff:.0f} / {t_prop:.0f} | {phone_rss(total / 1e6):.0f} |")
    print()


def node():
    print("## Node segments (format 35) and the first-day count (format 41)\n")
    window_shape = [15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 0, 0, 8, 15, 15,
                    15, 15, 16]
    mask = 0x01F9FFFF
    rel_index = {name: i for i, (name, _) in enumerate(leaf.RELATIONS)}
    relations41 = leaf.RELATIONS + [("Poseidon2Call", 16)]
    rel_index["Poseidon2Call"] = len(leaf.RELATIONS)
    gates_per_constraint = 2850 / 815

    def family_chip(comp, extra_pre=0):
        main, fr = comp["main"], comp["fractions"]
        inter = interaction(fr)
        rel = 0
        for r in comp["relations"]:
            rel |= 1 << rel_index[r.replace("LookupElements", "")]
        cons = comp["constraints"] + math.ceil(fr / 2)
        return {"name": "CPU family", "preprocessed": extra_pre,
                "main": [("Current", main - 1), ("Next", 1)],
                "interaction": [("Current", inter - 4), ("Previous", 4)],
                "relations": rel, "gates": round(gates_per_constraint * cons),
                "constraints": cons}

    cpu41 = dict(leaf.CHIPS[0])
    cpu41.update({"main": [("Current", 56), ("Next", 1), ("Current", 524)],
                  "interaction": [("Current", 196), ("Previous", 4)],
                  "relations": leaf.CHIPS[0]["relations"] | 1 << rel_index["Poseidon2Call"],
                  "gates": 2850 + 35, "constraints": 826})
    program_memory_split = dict(leaf.CHIPS[11])
    program_memory_split["preprocessed"] += 1

    # The Poseidon2 chip (pin H) as a node kernel calling 0x402 would hold
    # it: 1,063 columns in the device count, of which 133 QM31 interaction
    # columns (532) and the blinding's 4, so 527 main; its constraints
    # [est] the device shape's 4,256 less the other chips' (about 2,600).
    p2_chip = {"name": "POSEIDON2", "preprocessed": 0, "main": [("Current", 527)],
               "interaction": [("Current", 528), ("Previous", 4)],
               "relations": 1 << rel_index["Poseidon2Call"] | 1 << rel_index["MemoryAccess"]
               | 1 << rel_index["Range256"],
               "gates": round(gates_per_constraint * 2600), "constraints": 2600}

    def shape_rows(sizes, cpu_chips, family_id=False, with_p2=False):
        chips = [(p2_chip, 10)] if with_p2 else []
        for i in range(25):
            if not mask >> i & 1:
                continue
            if i == 0:
                chips += cpu_chips
            elif i == 11 and family_id:
                chips.append((program_memory_split, sizes[i]))
            else:
                chips.append((leaf.CHIPS[i], sizes[i]))
        t = leaf.leaf_terms(chips, relations41)
        return t["finalized"], t["columns"]

    # The window kernel's class 1 (2^15 steps): its family rows from the
    # window kernel's first 2^15-step chunk.
    w = WINDOWS[("window/52178", "chunk15", 0)]
    rows = family_rows(w["mix"])
    steps = w["to"] - w["from"]
    rows = {f: n * (1 << 15) / steps for f, n in rows.items()}
    code_ops = set(CODE["window/52178"])
    print(f"The window kernel's class 1 (2^15 steps, mask {mask:#x}); its first chunk by family"
          f" {dict((f, round(n)) for f, n in rows.items())}.\n")
    print("| shape | CPU components (columns at log) | columns | `p2` / `qm31` / `h8` rows |"
          " fits 2^16 / 2^17 / 2^16 |")
    print("|---|---|---|---|---|")
    base35 = leaf.leaf_terms(leaf.segment_chips(mask, window_shape))
    print(f"| format 35 (today) | 772 at 15 | {base35['columns']} |"
          f" {' / '.join(map(str, base35['finalized']))} | yes |")
    r41, c41 = shape_rows(window_shape, [(cpu41, 15)])
    print(f"| 41: the shared CPU (`CpuP2`), no Poseidon2 chip | 781 at 15 | {c41} |"
          f" {' / '.join(map(str, r41))} | {fits(r41)} |")
    out = {}
    for pruned in (False, True):
        for variant in VARIANTS:
            if variant == "today" and not pruned:
                continue
            comps = []
            for families in VARIANTS[variant]:
                comp = component(families, code_ops if pruned else None, (1024, 1025))
                if comp is None:
                    continue
                n = sum(rows.get(f, 0) for f in families)
                log = 15 if variant == "today" else max(4, log2ceil(n))
                comps.append((family_chip(comp, 0), log, comp))
            r, c = shape_rows(window_shape, [(chip, log) for chip, log, _ in comps],
                              family_id=variant != "today")
            desc = " + ".join(f"{comp['main'] + interaction(comp['fractions'])} at {log}"
                              for _, log, comp in comps)
            label = ("41, " + variant) + (", per program" if pruned else "")
            out[label] = r
            print(f"| {label} | {desc} | {c} | {' / '.join(map(str, r))} | {fits(r)} |")
            comps_p2 = []
            for families in VARIANTS[variant]:
                comp = component(families, (code_ops | {"Ecalli"}) if pruned else None,
                                 (1024, 1025, 1026))
                if comp is None:
                    continue
                n = sum(rows.get(f, 0) for f in families)
                log = 15 if variant == "today" else max(4, log2ceil(n))
                comps_p2.append((family_chip(comp, 0), log))
            rp, cp = shape_rows(window_shape, comps_p2, family_id=variant != "today",
                                with_p2=True)
            print(f"| {label}, with the Poseidon2 chip | | {cp} | {' / '.join(map(str, rp))} |"
                  f" {fits(rp)} |")
    rp, cp = shape_rows(window_shape, [(cpu41, 15)], with_p2=True)
    print(f"| 41: `CpuP2` with the Poseidon2 chip (a kernel calling 0x402) | 781 at 15 | {cp} |"
          f" {' / '.join(map(str, rp))} | {fits(rp)} |")
    deep_mem = list(window_shape)
    deep_mem[3] = 19
    rm, _ = shape_rows(deep_mem, [(cpu41, 15)])
    print(f"\nThe byte ledger at 2^19 instead of 2^18 (41's CPU): {' / '.join(map(str, rm))},"
          f" {rm[0] - r41[0]:+d} `p2` rows.")
    # Headroom: today's CpuP2 widened by k single-mask main columns.
    for extra in range(0, 4000, 8):
        wide = dict(cpu41)
        wide["main"] = cpu41["main"] + [("Current", extra)]
        rr, _ = shape_rows(window_shape, [(wide, 15)])
        if not all(x <= y for x, y in zip(rr, leaf.PADDED)):
            print(f"\nHeadroom: `CpuP2` widened by {extra} columns first passes the padded"
                  f" shape ({' / '.join(map(str, rr))}); {extra - 8} fit.")
            break
    print()
    # Node cells, format 35 (unmasked: columns at their rows), by segment.
    print("Node segment cells (format 35, the CPU's columns × rows; the other chips"
          " unchanged), per 2^15-step chunk of the traced node kernels:\n")
    print("| kernel chunk | today's segment cells | CPU share | 4-way | 4-way per program |"
          " per program (one CPU) |")
    print("|---|---|---|---|---|---|")
    for (kernel, kind, start), w in sorted(WINDOWS.items()):
        if kind != "chunk15" or kernel.startswith("device") or w["to"] - w["from"] < 1 << 15:
            continue
        sizes = w["log_sizes"]
        seg = 0
        for i in range(25):
            if mask >> i & 1:
                ch = leaf.CHIPS[i]
                cols = ch["preprocessed"] + sum(n for _, n in ch["main"]) + sum(
                    n for _, n in ch["interaction"])
                seg += cols * (1 << sizes[i])
        cpu_cells = 772 * (1 << sizes[0])
        rows_c = family_rows(w["mix"])
        code_ops = set(CODE[kernel])
        line = []
        for variant, pruned in (("4-way (ALU | memory | control | host)", False),
                                ("4-way (ALU | memory | control | host)", True),
                                ("today", True)):
            comps = split_components(variant, rows_c, code_ops if pruned else None, (1024, 1025),
                                     masked=False, floor=4, steps=w["to"] - w["from"])
            cells = sum(c * (1 << l) for c, l, *_ in comps)
            line.append(f"{100 * (cells - cpu_cells) / seg:+.1f}%")
        print(f"| {kernel} @{start} | {fmt_m(seg)} | {100 * cpu_cells / seg:.0f}% | "
              + " | ".join(line) + " |")
    print()
    print("At each kernel's class shape (every family at its largest size over the"
          " kernel's full chunks, as `canonical_profile_for_bounds` pads a class):\n")
    print("| kernel | family logs (class) | 4-way | 4-way per program |")
    print("|---|---|---|---|")
    kernels = sorted({k for (k, kind, _) in WINDOWS if kind == "chunk15" and not k.startswith("device")})
    for kernel in kernels:
        chunks = [w for (k, kind, _), w in WINDOWS.items()
                  if k == kernel and kind == "chunk15" and w["to"] - w["from"] == 1 << 15]
        if not chunks:
            continue
        code_ops = set(CODE[kernel])
        worst = {}
        for w in chunks:
            for f, n in family_rows(w["mix"]).items():
                worst[f] = max(worst.get(f, 0), n)
        line = []
        for pruned in (False, True):
            comps = split_components("4-way (ALU | memory | control | host)", worst,
                                     code_ops if pruned else None, (1024, 1025),
                                     masked=False, floor=4)
            deltas = []
            for w in chunks:
                seg = 0
                for i in range(25):
                    if mask >> i & 1:
                        ch = leaf.CHIPS[i]
                        seg += (ch["preprocessed"] + sum(n for _, n in ch["main"])
                                + sum(n for _, n in ch["interaction"])) * (1 << w["log_sizes"][i])
                cells = sum(c * (1 << l) for c, l, *_ in comps)
                deltas.append((cells - 772 * (1 << 15)) / seg)
            line.append(f"{100 * max(deltas):+.1f}…{100 * min(deltas):+.1f}%")
        logs = {f: log2ceil(n) for f, n in worst.items()}
        print(f"| {kernel} | {logs} | " + " | ".join(line) + " |")
    print()
    return out


def fits(rows):
    return "yes" if all(r <= p for r, p in zip(rows, leaf.PADDED)) else "**no**"


def calibration():
    a, b = PHONE_FIT
    ra, rb = PHONE_RSS_FIT
    xa, xb = X86_FIT
    print("## Time against cells [measured points, fits]\n")
    print(f"- phone: affine {a:.0f} ms + {b:.1f} ms per M cells; proportional"
          f" {PHONE_PER_CELL:.1f} ms per M cells; residuals:"
          + ", ".join(f" {c:.1f}M: {t} vs {a + b * c:.0f} / {PHONE_PER_CELL * c:.0f}"
                      for c, t, _ in PHONE))
    pa, pb = fit([(c, r) for c, _, r in PHONE[:3]])
    print(f"- phone peak: {ra:.0f} MiB + {rb:.1f} MiB per M cells; 1 GiB at"
          f" {(1024 - ra) / rb:.1f}M cells; P6's three points alone: {pa:.0f} + {pb:.1f},"
          f" 1 GiB at {(1024 - pa) / pb:.1f}M cells")
    print(f"- x86 (4 P-cores, one session): {xa:.0f} ms + {xb:.1f} ms per M cells;"
          f" phone/x86 at 11.7M {607 / 328:.2f}, at 19.7M {952 / 472:.2f}\n")


def table_components_by_kernel():
    print("## Per-program components (the kernel's code opcodes alone)\n")
    print("| kernel | component | opcodes in code | main | fractions | device columns |")
    print("|---|---|---|---|---|---|")
    for kernel in ("device/auth", "window/52178", "accounts/248914"):
        code_ops = set(CODE[kernel])
        calls = (1025, 1026) if kernel.startswith("device") else (1024, 1025)
        for variant in ("today", "4-way (ALU | memory | control | host)"):
            for families in VARIANTS[variant]:
                comp = component(families, code_ops, calls)
                if comp is None:
                    continue
                cols = comp["main"] + interaction(comp["fractions"]) + 4
                print(f"| {kernel} | {variant}: {'+'.join(sorted(families))} |"
                      f" {len(comp['ops'])} | {comp['main']} | {comp['fractions']} | {cols} |")
    print()


if __name__ == "__main__":
    table_histogram()
    table_widths()
    table_components_by_kernel()
    calibration()
    table_auth()
    table_heavy()
    budgets()
    crossover()
    levers()
    node()
