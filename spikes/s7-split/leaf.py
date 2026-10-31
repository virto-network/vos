"""A kernel leaf's rows from its shape: `vos_pvm_compiler::leaf`, ported.

The chips' AIR tables are read from `pvm/compiler/src/leaf.rs` itself, so the
port follows the derivation's own counts; `leaf_terms` is the Rust
function's arithmetic over a list of chips (a chip of the segment AIR, or a
CPU family chip the split would add), so a shape whose CPU is several
components can be counted the same way.
"""

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
LEAF_RS = os.path.join(HERE, "..", "..", "pvm", "compiler", "src", "leaf.rs")

LOG_BLOWUP = 2
QUERIES = 40
PADDED = (1 << 16, 1 << 17, 1 << 16)
FINALIZE = 512
LEAF_WORK = (2 * 19 + 7, 85 + 448 + 2)
BOUNDARY_TERMS = 644
HEADER_WORDS = 9
ROOTS_AND_BOUNDARY = 2 + 37
COMPOSITION_STEPS = 4
DEEP_COEFFICIENT = 1
LAST_LAYER = 1
POW = (6, 246, 0)
CONTEXT = (0, 2, 0)
OODS_ROWS = 4 + 2 + 1 + 2 * 3 + 1 + 1
PREPROCESSED_ROOT_WORDS = 2
GROUP = 1 << 31


def parse_leaf_rs(path=LEAF_RS):
    """`RELATIONS` and `CHIPS` as the Rust source declares them."""
    text = open(path).read()
    rel_block = text[text.index("pub const RELATIONS"):text.index("];", text.index("pub const RELATIONS"))]
    relations = [(name, int(size)) for name, size in re.findall(r'\("(\w+)", (\d+)\)', rel_block)]
    chips_block = text[text.index("pub const CHIPS"):]
    chips_block = chips_block[:chips_block.index("\n];")]
    chips = []
    for name, body in re.findall(r"// (\w+)\n\s*Chip \{(.*?)\n    \},", chips_block, re.S):
        def runs(field):
            m = re.search(field + r": &\[(.*?)\],", body, re.S)
            return [(mask, int(n)) for mask, n in re.findall(r"\((\w+), (\d+)\)", m.group(1))]
        chips.append({
            "name": name,
            "preprocessed": int(re.search(r"preprocessed: (\d+)", body).group(1)),
            "main": runs("main"),
            "interaction": runs("interaction"),
            "relations": int(re.search(r"relations: (0x[0-9a-f_]+)", body).group(1).replace("_", ""), 16),
            "gates": int(re.search(r"gates: (\d+)", body).group(1)),
            "constraints": int(re.search(r"constraints: (\d+)", body).group(1)),
        })
    assert len(chips) == 25, len(chips)
    return relations, chips


RELATIONS, CHIPS = parse_leaf_rs()


def generator(log_size):
    return 1 << (31 - log_size)


def sample_points(column, lifting):
    log_size, mask = column
    step = generator(lifting - LOG_BLOWUP)
    if mask == "Current":
        return [0]
    offsets = (0, step) if mask == "Next" else (GROUP - step, 0)
    period = (generator(lifting) << log_size) % GROUP
    return [(offsets[1] + period) % GROUP, offsets[0], offsets[1]]


def domain_point_rows(log_size):
    return 2 + 4 * (log_size - 2) + 1


def fri_fold_rows(layers):
    return 5 * layers + (layers - 2)


def linear_rows(n):
    return 1 + -(-max(n - 3, 0) // 2)


def deep(trees, lifting):
    samples = []
    exponent = 0
    for tree in trees:
        cols = []
        for column in tree:
            pts = []
            for point in sample_points(column, lifting):
                pts.append((point, exponent))
                exponent += 1
            cols.append(pts)
        samples.append(cols)
    by_point = {}
    for tree in samples:
        for col in tree:
            for point, e in col:
                by_point.setdefault(point, []).append(e)
    items = {}
    taken = set()
    blocks = 0
    for t, tree in enumerate(trees):
        order = sorted(range(len(tree)), key=lambda c: tree[c][0])
        for k in range(0, len(order) - len(order) % 8, 8):
            lanes = order[k:k + 8]
            for point, exps in sorted(by_point.items()):
                at = []
                for c in lanes:
                    hits = [s for s in samples[t][c] if s[0] == point]
                    if len(hits) != 1:
                        at = None
                        break
                    at.append(hits[0][1])
                if at is None:
                    continue
                low, high = at[0], at[7]
                step = at[1] - low
                if step <= 0:
                    continue
                stepped = all(e == low + j * step for j, e in enumerate(at))
                alone = sum(1 for e in exps if low <= e <= high) == 8
                if stepped and alone:
                    blocks += 1
                    items.setdefault(point, []).append((low, high, step))
                    for c in lanes:
                        taken.add((t, c, point))
    singles = 0
    for t, tree in enumerate(samples):
        for c, col in enumerate(tree):
            for point, e in col:
                if (t, c, point) not in taken:
                    singles += 1
                    items.setdefault(point, []).append((e, e, 0))
    # once rows
    powers, conjugates = set(), set()
    point_rows = 0
    for point, exps in by_point.items():
        exps = sorted(exps, reverse=True)
        for a, b in zip(exps, exps[1:]):
            powers.add(a - b)
            conjugates.add(a - b)
        lowest = exps[-1]
        powers.add(lowest)
        conjugates.add(lowest)
        pit = sorted(items[point], key=lambda x: -x[1])
        for a, b in zip(pit, pit[1:]):
            powers.add(a[0] - b[0])
        for _, _, step in pit:
            if step > 0:
                powers.add(step)
        point_rows += 13 + 2 * len(exps) + 3 * (lowest > 0)
    powers.discard(0)
    conjugates.discard(0)
    squarings = max(powers).bit_length() - 1 if powers else 0
    products = sum(bin(p).count("1") - 1 for p in powers)
    once = squarings + products + len(conjugates) + point_rows
    return {"points": len(by_point), "blocks": blocks, "singles": singles, "once": once}


def leaf_terms(chips, relations=RELATIONS):
    """`chips`: a list of (chip dict, log size). The rows by piece."""
    n = len(chips)
    max_log = max(log for _, log in chips)
    lifting = max_log + LOG_BLOWUP
    fri_layers = max_log

    def expand(runs, log):
        return [(log + LOG_BLOWUP, mask) for mask, count in runs for _ in range(count)]

    trees = [[], [], [], []]
    for chip, log in chips:
        trees[0] += expand([("Current", chip["preprocessed"])], log)
        trees[1] += expand(chip["main"], log)
        trees[2] += expand(chip["interaction"], log)
    trees[3] = expand([("Current", 8)], lifting - LOG_BLOWUP)
    samples = sum(min(len(sample_points(c, lifting)), 2) for tree in trees for c in tree)
    drawn = 0
    for chip, _ in chips:
        drawn |= chip["relations"]
    preprocessed_height = max(c[0] for c in trees[0])
    d = deep(trees, lifting)
    q = QUERIES
    header = HEADER_WORDS + n
    leaves = sum(-(-(len(tree) + 1) // 8) for tree in trees)
    paths = preprocessed_height + 3 * lifting
    fri = sum(3 + lifting - 1 - layer for layer in range(fri_layers))
    channel = (header + ROOTS_AND_BOUNDARY + bin(drawn).count("1") + -(-n // 2)
               + COMPOSITION_STEPS + -(-samples // 2) + DEEP_COEFFICIENT + 2 * fri_layers
               + LAST_LAYER)
    powers = sum(max(size - 2, 0) for r, (_, size) in enumerate(relations) if drawn >> r & 1)
    gates = sum(chip["gates"] for chip, _ in chips)
    constraints = sum(chip["constraints"] for chip, _ in chips)
    terms = {
        "channel": (channel, 0, 0),
        "pow": POW,
        "queries": (-(-q // 8), 64 * q, 0),
        "circle": (0, domain_point_rows(lifting) * q, 0),
        "merkle": ((leaves + paths) * q, 0, 0),
        "fri": (fri * q, fri_fold_rows(fri_layers) * q, 0),
        "deep": (0, (d["singles"] + 6 * d["points"]) * q, d["blocks"] * q),
        "deep_once": (0, d["once"], 0),
        "oods": (0, gates + powers + constraints - 1 + 2 * (max_log - 1) + OODS_ROWS, 0),
        "logup": (0, linear_rows(n) + BOUNDARY_TERMS, 0),
        "shape": (0, header + PREPROCESSED_ROOT_WORDS, 0),
        "context": CONTEXT,
        "leaf": (LEAF_WORK[0], LEAF_WORK[1], 0),
    }
    rows = tuple(sum(t[i] for t in terms.values()) for i in range(3))
    columns = sum(len(t) for t in trees)
    return {"rows": rows, "terms": terms, "deep": d, "columns": columns,
            "finalized": (rows[0], rows[1] + FINALIZE, rows[2])}


def segment_chips(mask, log_sizes):
    return [(CHIPS[i], log_sizes[i]) for i in range(25) if mask >> i & 1]


if __name__ == "__main__":
    window = [15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 0, 0, 8, 15, 15, 15, 15, 16]
    t = leaf_terms(segment_chips(0x01F9FFFF, window))
    d = t["deep"]
    print(t["rows"], (d["points"], d["blocks"], d["singles"]), t["terms"]["merkle"][0],
          t["terms"]["oods"][1], t["terms"]["deep_once"][1])
    assert t["rows"] == (57_700, 102_173, 46_000), t["rows"]
    assert (d["points"], d["blocks"], d["singles"]) == (16, 1_150, 785)
    print("the window kernel's class-1 leaf matches vos_pvm_compiler::leaf")
