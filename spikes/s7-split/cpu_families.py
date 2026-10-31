"""The CPU chip's columns by opcode family, from its own constraints.

`runs/cpu-family-usage.json` is the CPU's AIR as `dump.patch`'s test writes it:
each constraint function's constraints (as expressions over the main
columns), its relation entries (relation, multiplicity, the tuple's columns),
the column layout, and every opcode's 80 program-memory flags.

A component that holds only some opcodes' rows has every other flag column
identically zero. `reduce(present)` substitutes those zeros and propagates:
a constraint left linear in one column, vanishing at zero, zeroes that column
too (a helper `h - flag * x` with `flag = 0`); a constraint left with no
column is dropped; a relation entry whose multiplicity vanishes is dropped; a
column no surviving entry reads and whose surviving constraints read it alone
(a boolean on a flag nothing else reads) is dropped. Identities are decided by
evaluation at random points over M31 (Schwartz-Zippel).
"""

import json
import os
import random
import re

P = (1 << 31) - 1
HERE = os.path.dirname(os.path.abspath(__file__))

# The 80 program-memory flags, by index (`classify_opcode_for_program_memory`):
# the CPU column each pins, or None for the four sums (bitwise, compare,
# branch, store) and the remainder bit of DivRemOp.
PM_FLAGS = (
    ["IsAdd", "IsSub", "IsMul", "IsSharR", None, "IsShift", None, "IsMove",
     "Is32Bit", None, "IsJump", "IsDivRem", "IsLoad", None, "IsExit",
     "IsNegAdd", "IsReverseBytes", "IsZeroExt16", "IsSignExt8", "IsSignExt16",
     "IsTrap", "IsJumpInd", "IsLoadImmJumpInd", "IsMulUpperUU", "IsMulUpperSU",
     "IsMulUpperSS", "IsDivS", "IsLoadI8", "IsLoadI16", "IsLoadI32",
     "IsMemSize1", "IsMemSize2", "IsMemSize4", "IsMemSize8", "IsStoreDirect",
     "IsLoadDirect", "IsMemIndirect", "IsStoreImmAny", "IsStoreImmDirect",
     "IsStoreInd", "IsRotateL64", "IsCountSetBits", "IsLzb", "IsTzb",
     "IsRotateR64", "IsRotateL32", "IsRotateR32", "IsImmAlt",
     "ValBIsReg", "ValBFromA", "ValDIsReg", "ResultIsReg", "ResultToD", None,
     "IsSetGt", "IsCmovImm",
     "IsSetLtU", "IsSetLtS", "IsCmovIz", "IsCmovNz", "IsMinS", "IsMinU",
     "IsMaxS", "IsMaxU",
     "IsBrEq", "IsBrNe", "IsBrLtU", "IsBrGeU", "IsBrLeU", "IsBrGtU", "IsBrLtS",
     "IsBrGeS", "IsBrLeS", "IsBrGtS",
     "IsAnd", "IsOr", "IsXor", "IsAndInv", "IsOrInv", "IsXnor"]
)
assert len(PM_FLAGS) == 80

# Selectors outside the program-memory flags, each tied to the opcodes (or
# host calls) that can set it.
EXTRA_SELECTORS = {
    "IsHaltJumpInd": lambda ops, calls: "JumpInd" in ops,
    "IsHaltLoadImmJumpInd": lambda ops, calls: "LoadImmJumpInd" in ops,
    "IsBlakeEcall": lambda ops, calls: 1024 in calls,
    "IsWitnessEcall": lambda ops, calls: 1025 in calls,
    "IsP2Ecall": lambda ops, calls: 1026 in calls,
    "HostCallAcknowledged": lambda ops, calls: "Ecalli" in ops,
    "HostCallPrecompileDispatch": lambda ops, calls: bool(calls),
    "DivRemOp": lambda ops, calls: any(o.startswith(("Div", "Rem")) for o in ops),
}

# The witnesses today's CPU computes on every row whatever its opcode: each
# group's consumers (the constraint functions and relation tuples that read
# it, each gated by its opcodes' flags), as a test on the flags a
# component's opcodes set, and its columns. A component none of whose
# opcodes consumes a group drops it and every constraint and relation entry
# touching it: its definitions, its range and nibble lookups, its consumers
# (whose gates are zero there).
COMPARES = {"IsSetLtU", "IsSetLtS", "IsCmovIz", "IsCmovNz", "IsMinS", "IsMinU", "IsMaxS",
            "IsMaxU"}
BRANCHES = {"IsBrEq", "IsBrNe", "IsBrLtU", "IsBrGeU", "IsBrLeU", "IsBrGtU", "IsBrLtS",
            "IsBrGeS", "IsBrLeS", "IsBrGtS"}
GROUPS = {
    # ValD's zero test, both ways (`divrem::zero_divisor_helpers`): every
    # compare (`IsCmpVdzH`), division by zero (every DivRem row, the
    # logical right shifts among them) and the trailing-zero count.
    "val_d_zero": (lambda f: bool(f & (COMPARES | {"IsDivRem", "IsLzb", "IsTzb"})),
                   ["ValDByteInv", "ValDPartialNZ", "ValDByteIndicatorH",
                    "ValDByteIndMinus1H", "PartNZTimesIndH", "ValDIsZero"]),
    # The remainder's zero test (`divrem::remainder_sign`): signed division.
    "rem_zero": (lambda f: "IsDivS" in f,
                 ["ValRByteInv", "ValRPartialNZ", "ValRByteIndicatorH", "ValRByteIndMinus1H",
                  "ValRPartNZTimesIndH"]),
    # The MSB-side prefix chains (`bitmanip::msb_helpers`): leading zeros.
    "msb": (lambda f: "IsLzb" in f,
            ["ValDPartialNZMsb", "ValDPartialNZMsbLo", "PartNZMsbTimesIndH",
             "PartNZMsbLoTimesIndH"]),
    # Quotient and remainder with their signs (the DivRem tuple).
    "div": (lambda f: "IsDivRem" in f,
            ["DivQuotient", "DivRemainder", "DivByZero", "SignBitQ", "SignBitR", "SignSrcQ",
             "SignSrcR", "SignQHiNib", "SignRHiNib"]),
    # The operands' signs (`signs`): compares and branches (`CmpLtSFlag`),
    # and the Mul and DivRem tuples.
    "operand_signs": (lambda f: bool(f & (COMPARES | BRANCHES | {"IsMul", "IsDivRem"})),
                      ["SignBitB", "SignBitD", "SignSrcB", "SignSrcD", "SignBHiNib",
                       "SignDHiNib", "SignsDiffH"]),
    # A 32-bit result's sign extension (`signs`, `alu`).
    "result_sign": (lambda f: "Is32Bit" in f, ["SignBitResult", "ResultHiNib"]),
    # A signed load's extension (`memory::signed_load_extension`).
    "load_sign": (lambda f: bool(f & {"IsLoadI8", "IsLoadI16", "IsLoadI32"}),
                  ["LoadSignBit", "LoadSignHiNib", "LoadSignSrc"]),
    # 32-bit truncation of ALU operands (`registers::register_helpers`).
    "truncation": (lambda f: "Is32Bit" in f,
                   ["IsTruncated", "ValBIsRegTruncH", "NonShiftGateTruncH", "Real32bitH"]),
    # Operand equality and less-than (`compare`, `control::branch_conditions`).
    "compare": (lambda f: bool(f & (COMPARES | BRANCHES)),
                ["EqFlag", "EqDiffSquaresH", "EqDiffSquaresInv", "EqDiffSquaresTimesInvH",
                 "IsCmpOrBranchEqH", "CmpLtFlag", "CmpLtSFlag"]),
    # The host calls' slots (`host_call`): BLAKE2b's five, the other
    # precompiles' pointers among them.
    "host_slots": (lambda f: "IsExit" in f and "HostCall" in f,
                   ["HPtr", "MPtr", "TLow", "Flag", "FlagInv", "FlagBool", "RealNotFlagBoolH",
                    "RealFlagBoolH", "FlagTimesInvH"]),
}

# The relations that are fixed tables: a lookup into one constrains its
# tuple and carries nothing to another chip.
TABLES = {"Range256", "BitwiseAnd", "ByteToBits", "Popcount", "Bitcount", "PowerOfTwo"}

# Host-call ids: BLAKE2b's compression, the witness input, Poseidon2.
HOST_CALLS = (1024, 1025, 1026)


class Cpu:
    def __init__(self, path=os.path.join(HERE, "runs", "cpu-family-usage.json")):
        d = json.load(open(path))
        self.names = {}
        for col in d["columns"]:
            for i in range(col["size"]):
                self.names[col["offset"] + i] = col["name"]
        self.names[d["is_p2"]] = "IsP2Ecall"
        self.n_main = d["is_p2"] + 1
        self.by_name = {}
        for idx, name in self.names.items():
            self.by_name.setdefault(name, []).append(idx)
        self.constraints = []  # (function, cols, compiled)
        self.fractions = []  # (function, relation, mult cols, mult compiled, tuple cols)
        for f in d["functions"]:
            for k in f["constraints"]:
                self.constraints.append((f["fn"], frozenset(k["cols"]), _compile(k["py"])))
            for fr in f["fractions"]:
                self.fractions.append((f["fn"], fr["relation"], frozenset(fr["mult"]),
                                       _compile(fr["mult_py"]), frozenset(fr["tuple"])))
        self.opcodes = {o["op"]: [PM_FLAGS[i] for i, v in enumerate(o["flags"])
                                  if v and PM_FLAGS[i] is not None]
                        for o in d["opcodes"]}
        self.flag_columns = {n for n in PM_FLAGS if n} | set(EXTRA_SELECTORS)

    def selectors_zero(self, ops, calls):
        """The flag columns no opcode of `ops` (nor host call of `calls`) sets."""
        live = set()
        for op in ops:
            live |= set(self.opcodes[op])
        for name, sets in EXTRA_SELECTORS.items():
            if sets(ops, calls):
                live.add(name)
        if any(op.startswith(("Shlo", "Shar", "Rot")) for op in ops):
            live.add("IsShiftConstrained")
        zero = set()
        for name in self.flag_columns | {"IsShiftConstrained"}:
            if name not in live:
                zero |= set(self.by_name[name])
        return zero

    def reduce(self, ops, calls=HOST_CALLS, prune=True, seed=1):
        """The main columns, constraints and relation entries a component
        holding only `ops`'s rows (and `calls`'s host calls) keeps. With
        `prune`, the witness groups (`GROUPS`) no opcode of `ops` consumes
        are removed with every entry touching them."""
        rng = random.Random(seed)
        zero = set(self.selectors_zero(ops, calls))
        points = [{(n, k): rng.randrange(P) for n in range(self.n_main) for k in (0, 1)}
                  for _ in range(2)]

        def env(point, zeroed, tweak=None):
            e = dict(point)
            for n in zeroed:
                e[(n, 0)] = 0
                e[(n, 1)] = 0
            if tweak is not None:
                e[(tweak[0], 0)] = tweak[1]
                e[(tweak[0], 1)] = tweak[1]
            return e

        def live_cols(f, cols, zeroed):
            out = set()
            for n in cols - zeroed:
                for pt in points:
                    base = f(env(pt, zeroed))
                    alt = f(env(pt, zeroed, (n, (pt[(n, 0)] + 12345) % P)))
                    if base != alt:
                        out.add(n)
                        break
            return out

        alive = list(range(len(self.constraints)))
        while True:
            changed = False
            keep = []
            boolean = set()
            for i in alive:
                _, cols, f = self.constraints[i]
                lc = live_cols(f, cols, zero)
                if len(lc) == 1:
                    (n,) = lc
                    if all(f(env(pt, zero, (n, 0))) == 0 and f(env(pt, zero, (n, 1))) == 0
                           and f(env(pt, zero, (n, 2))) != 0 for pt in points):
                        boolean.add(n)
            for i in alive:
                _, cols, f = self.constraints[i]
                lc = live_cols(f, cols, zero)
                if not lc:
                    v = [f(env(pt, zero)) for pt in points]
                    assert all(x == 0 for x in v), ("a constraint no zero row meets",
                                                     self.constraints[i][0])
                    changed = True
                    continue
                if len(lc) == 1:
                    (n,) = lc
                    at = lambda x, pt: f(env(pt, zero, (n, x)))
                    if all(at(0, pt) == 0 and at(2, pt) == (2 * at(1, pt)) % P for pt in points):
                        zero.add(n)
                        changed = True
                        continue
                elif lc <= boolean and self._positive_sum(f, lc, zero, points, env):
                    # A sum of booleans with positive coefficients, zero: each
                    # is zero (the sum is below p).
                    zero |= lc
                    changed = True
                    continue
                keep.append(i)
            alive = keep
            # A flag byte whose bits are all zero is zero (`ByteToBits`).
            for _, rel, mcols, mf, tcols in self.fractions:
                if rel.startswith("ByteToBits"):
                    left = tcols - zero
                    if len(left) == 1:
                        zero |= left
                        changed = True
            if not changed:
                break

        fracs = []
        for j, (_, rel, mcols, mf, tcols) in enumerate(self.fractions):
            if rel.replace("LookupElements", "") in TABLES and not tcols - zero:
                continue  # a constant's lookup
            if live_cols(mf, mcols, zero) or any(mf(env(pt, zero)) for pt in points):
                fracs.append(j)

        removed_items = []
        if prune:
            flags = set()
            for op in ops:
                flags |= set(self.opcodes[op])
            if "Ecalli" in ops and calls:
                flags.add("HostCall")
            gone = set()
            for name, (consumes, columns) in GROUPS.items():
                if not consumes(flags):
                    for col in columns:
                        gone |= set(self.by_name[col])
            gone -= zero
            keep = []
            for i in alive:
                if live_cols(self.constraints[i][2], self.constraints[i][1], zero) & gone:
                    removed_items.append(self.constraints[i][0])
                else:
                    keep.append(i)
            alive = keep
            keep = []
            for j in fracs:
                cols = (self.fractions[j][2] | self.fractions[j][4]) - zero
                if cols & gone:
                    removed_items.append(self.fractions[j][0] + ":" + self.fractions[j][1])
                else:
                    keep.append(j)
            fracs = keep
            zero = zero | gone

        # Live columns, a least fixpoint from what other chips read. A
        # surviving constraint is a definition when it is linear, with a
        # constant coefficient, in a column it alone defines (the helper the
        # AIR names for a product, a sign source, a carry), else a check. A
        # check over two or more columns makes them live; one over a single
        # column (a boolean, a constant) and a table lookup (range, nibble,
        # flag bits) only describe their columns, kept with them. A live
        # defined column makes its definition's columns live; a table lookup
        # holding a live column makes its other columns live.
        cons_live = {i: live_cols(self.constraints[i][2], self.constraints[i][1], zero)
                     for i in alive}
        frac_live = {j: (live_cols(self.fractions[j][3], self.fractions[j][2], zero)
                         | (self.fractions[j][4] - zero)) for j in fracs}
        is_table = {j: self.fractions[j][1].replace("LookupElements", "") in TABLES
                    for j in fracs}
        uses = {}
        for i in alive:
            for n in cons_live[i]:
                uses[n] = uses.get(n, 0) + 1
        for j in fracs:
            for n in frac_live[j]:
                uses[n] = uses.get(n, 0) + 1
        roots = set()
        for j in fracs:
            if not is_table[j]:
                roots |= frac_live[j]
        defines = {}
        defined_by = {}
        for i in sorted(alive, key=lambda i: len(cons_live[i])):
            f = self.constraints[i][2]
            if len(cons_live[i]) < 2:
                continue
            cands = []
            for n in cons_live[i]:
                if n in roots or n in defined_by:
                    continue
                d = [(f(env(pt, zero, (n, 1))) - f(env(pt, zero, (n, 0)))) % P for pt in points]
                lin = all(f(env(pt, zero, (n, 2))) == (2 * f(env(pt, zero, (n, 1)))
                                                        - f(env(pt, zero, (n, 0)))) % P
                          for pt in points)
                if lin and d[0] == d[1] != 0:
                    cands.append((uses[n], n))
            if cands:
                n = min(cands)[1]
                defines[i] = n
                defined_by[n] = i
        live = set(roots)
        for i in alive:
            if i not in defines and len(cons_live[i]) >= 2:
                live |= cons_live[i]
        while True:
            grow = set()
            for n in live:
                if n in defined_by:
                    grow |= cons_live[defined_by[n]]
            for j in fracs:
                if is_table[j] and frac_live[j] & live:
                    grow |= frac_live[j]
            if grow <= live:
                break
            live |= grow
        dropped = set(range(self.n_main)) - zero - live
        alive = [i for i in alive if cons_live[i] & live]
        fracs = [j for j in fracs if frac_live[j] & live or not frac_live[j]]
        main = set(range(self.n_main)) - zero - dropped
        return {
            "main": sorted(main),
            "constraints": len(alive),
            "fractions": len(fracs),
            "relations": sorted({self.fractions[j][1] for j in fracs}),
            "fraction_ids": fracs,
            "removed": removed_items,
        }

    @staticmethod
    def _positive_sum(f, lc, zero, points, env):
        """Whether `f` is, in the columns `lc`, a homogeneous linear form with
        coefficients all of one sign, each below 2^16."""
        for pt in points:
            z = {n: 0 for n in lc}
            base = dict(pt)
            for n in lc:
                base[(n, 0)] = base[(n, 1)] = 0
            e0 = env(base, zero)
            for n in lc:
                e0[(n, 0)] = e0[(n, 1)] = 0
            if f(e0) != 0:
                return False
            coefs = []
            for n in lc:
                e = dict(e0)
                e[(n, 0)] = e[(n, 1)] = 1
                coefs.append(f(e))
            e = dict(e0)
            for n in lc:
                e[(n, 0)] = e[(n, 1)] = 3
            if f(e) != (3 * sum(coefs)) % P:
                return False
            signed = [c if c < P // 2 else c - P for c in coefs]
            if not (all(0 < c < 1 << 16 for c in signed) or all(-(1 << 16) < c < 0 for c in signed)):
                return False
        return True

    def column_names(self, cols):
        out = {}
        for n in cols:
            out[self.names[n]] = out.get(self.names[n], 0) + 1
        return out


def _compile(expr):
    if expr.startswith("["):
        parts = expr[1:-1]
        # The four coordinates of a base-field constraint: the first alone.
        depth = 0
        for i, ch in enumerate(parts):
            depth += ch == "("
            depth -= ch == ")"
            if ch == "," and depth == 0:
                rest = parts[i + 1:]
                assert rest.replace(" ", "") == "0,0,0", rest
                parts = parts[:i]
                break
        expr = parts
    code = re.sub(r"c\((\d+),(\d+),(-?\d+)\)", r"e[(\2,\3)]", expr)
    code = compile(code, "<constraint>", "eval")
    return lambda e: eval(code, {"inv": _inv}, {"e": e}) % P


def _inv(x):
    x %= P
    return pow(x, P - 2, P) if x else 0
