#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# End-to-End Formal Verification & Falsifier Regression Suite for `quintessence`.
#
# Executes the compiled native `quintessence` binary across 14 live positive,
# firewall, K-CUT falsifier, TINI information-flow, MaxPlus slice-budget, binary
# tamper, vacuity, and ECHIDNA mutation test cases, asserting BOTH the exact
# error code (`Q-xxx`) AND the exact OS exit status (`0..5`).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BIN="$ROOT/src/interface/ffi/zig-out/bin/quintessence"
if [ ! -x "$BIN" ]; then
    echo "Building quintessence native binary..."
    (cd "$ROOT/src/interface/ffi" && zig build -Doptimize=ReleaseSafe)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

assert_case() {
    local label="$1"
    local want_exit="$2"
    local want_token="$3"
    shift 3

    set +e
    local out
    out="$("$BIN" "$@" 2>&1)"
    local got_exit=$?
    set -e

    if [ "$got_exit" -eq "$want_exit" ] && grep -qF -- "$want_token" <<<"$out"; then
        echo "  PASS  $label  (exit=$got_exit, matched '$want_token')"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label  (wanted exit=$want_exit + '$want_token', got exit=$got_exit)" >&2
        echo "$out" | sed 's/^/        /' >&2
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Quintessence 15-Case Live Formal Verification Suite ==="

# 1. Toolchain doctor check
assert_case "01. Toolchain doctor ready" 0 "Status: READY" \
    doctor

# 2. Full 3-layer positive verification on Verisim example (Z3 + CVC5 + Alethe + dlopen + Mutation)
assert_case "02. Full 3-layer Verisim vertical slice (12 QEDs + 100% mutation)" 0 "VERIFIED  TrustLevel=4  Obligations=12  MutationScore=100.00%  Exit=0" \
    verify examples/quintessence --out-dir "$WORK/ok_out"

# 3. G0a Firewall: dynamic Code.eval_string/1 -> Q-101, exit 1
cat > "$WORK/bad_eval.ex" <<'EX'
defmodule BadEval do
  use Quintessence.Face, layer: :a
  def run(s), do: Code.eval_string(s)
end
EX
assert_case "03. Firewall rejects Code.eval_string (Q-101)" 1 "[Q-101]" \
    verify "$WORK/bad_eval.ex" --out-dir "$WORK/o3"

# 4. G0c Firewall: dynamic apply/3 -> Q-102, exit 1
cat > "$WORK/bad_apply.ex" <<'EX'
defmodule BadApply do
  use Quintessence.Face, layer: :a
  def run(m, f, a), do: apply(m, f, a)
end
EX
assert_case "04. Firewall rejects dynamic apply/3 (Q-102)" 1 "[Q-102]" \
    verify "$WORK/bad_apply.ex" --out-dir "$WORK/o4"

# 5. Layer A purity: Process.put inside Layer A -> Q-103, exit 1
cat > "$WORK/bad_impure.ex" <<'EX'
defmodule BadImpure do
  use Quintessence.Face, layer: :a
  def write_dict(x), do: Process.put(:secret, x)
end
EX
assert_case "05. Firewall rejects Process.put in Layer A (Q-103)" 1 "[Q-103]" \
    verify "$WORK/bad_impure.ex" --out-dir "$WORK/o5"

# 6. Layer C boundary seal: raw :erlang.load_nif outside Quintessence.Nif -> Q-105, exit 1
cat > "$WORK/bad_raw_nif.ex" <<'EX'
defmodule BadRawNif do
  use Quintessence.Face, layer: :a
  def init_nif(p), do: :erlang.load_nif(p, 0)
end
EX
assert_case "06. Firewall rejects unverified :erlang.load_nif (Q-105)" 1 "[Q-105]" \
    verify "$WORK/bad_raw_nif.ex" --out-dir "$WORK/o6"

# 7. Total recursion check: diverging recursion -> Q-203, exit 1
cat > "$WORK/bad_term.ex" <<'EX'
defmodule BadTerm do
  use Quintessence.Face, layer: :a
  @pre spec(n >= 0)
  @measure spec(n)
  def diverge(n), do: diverge(n + 1)
end
EX
assert_case "07. Z3 refutes non-decreasing recursive @measure (Q-203)" 1 "[Q-203]" \
    verify "$WORK/bad_term.ex" --out-dir "$WORK/o7"

# 8. Secret lattice TINI 2-safety relational leak -> Q-206, exit 1
cat > "$WORK/bad_tini.ex" <<'EX'
defmodule BadTini do
  use Quintessence.Face, layer: :a
  @secret [api_key: :confidential, nonce: :public]
  @pre spec(api_key >= 0 and nonce >= 0)
  @post spec(result >= 0)
  def leak(api_key, nonce), do: api_key + nonce
end
EX
assert_case "08. TINI relational product catches confidential leak (Q-206)" 1 "[Q-206]" \
    verify "$WORK/bad_tini.ex" --out-dir "$WORK/o8"

# 9. NON-NEGOTIABLE FALSIFIER: remote commit claimed across async `:cast` -> Q-401, exit 1
cat > "$WORK/bad_kcut_cast.ex" <<'EX'
defmodule BadKCutCast do
  use GenServer
  use Quintessence.Face, layer: :b

  @choreography [
    roles: [:client, :entity],
    messages: [
      {:client, :entity, :commit, [:payload]}
    ],
    knowledge: [
      {:client, :entity, :committed, [:version], {:cast, :commit}}
    ]
  ]

  def handle_cast({:commit, _payload}, state), do: {:noreply, state}
end
EX
assert_case "09. Pre-registered falsifier: K-CUT rejects commit claim over cast (Q-401)" 1 "[Q-401]" \
    verify "$WORK/bad_kcut_cast.ex" --out-dir "$WORK/o9"

# 10. Layer C MaxPlus slice violation: WCET > 1,000 us on normal scheduler -> Q-305, exit 1
mkdir -p "$WORK/overbudget/lib" "$WORK/overbudget/priv/native"
cat > "$WORK/overbudget/lib/slow_nif.ex" <<'EX'
defmodule SlowNif do
  use Quintessence.Nif,
    otp_app: :slow,
    library: "slow_nif",
    abi: Slow.Abi,
    receipt: "priv/receipts/slow.receipt.json"

  @nif :heavy, schedule: :normal, budget_us: 3000
  def heavy(x), do: :erlang.nif_error(:nif_not_loaded)
end
EX
cat > "$WORK/overbudget/priv/native/slow_nif.zig" <<'ZIG'
export fn slow_heavy(x: u32) callconv(.c) u32 {
    var acc: u32 = x;
    for (0..100000) |i| {
        acc +%= @intCast(i);
    }
    return acc;
}
ZIG
assert_case "10. MaxPlus rejects >1000us NIF without :dirty_cpu (Q-305)" 1 "[Q-305]" \
    verify "$WORK/overbudget/lib/slow_nif.ex" --out-dir "$WORK/o10"

# 11. Layer C binary tamper check: 1-byte flip in compiled .so -> Q-303, exit 4
cp "examples/quintessence/priv/native/libverisim_nif.so" "$WORK/tampered_verisim.so"
printf '\xff' | dd of="$WORK/tampered_verisim.so" bs=1 seek=64 count=1 conv=notrunc status=none
assert_case "11. Load-time integrity rejects 1-byte tampered .so (Q-303)" 4 "[Q-303]" \
    receipt verify "examples/quintessence/priv/receipts/verisim_nif.receipt.json" --binary "$WORK/tampered_verisim.so"

# 12. Vacuity Probe V1: contradictory @pre -> Q-601, exit 5
cat > "$WORK/vacuous_pre.ex" <<'EX'
defmodule VacuousPre do
  use Quintessence.Face, layer: :a
  @pre spec(x > 100 and x < 50)
  @post spec(result == 999)
  def impossible(x), do: x
end
EX
assert_case "12. Vacuity V1 rejects unsatisfiable @pre (Q-601, exit 5)" 5 "[Q-601]" \
    verify "$WORK/vacuous_pre.ex" --out-dir "$WORK/o12"

# 13. Vacuity Probe V2: tautological @post -> Q-602, exit 5
cat > "$WORK/trivial_post.ex" <<'EX'
defmodule TrivialPost do
  use Quintessence.Face, layer: :a
  @pre spec(x >= 0)
  @post spec(result == result)
  def tautology(x), do: x + 1
end
EX
assert_case "13. Vacuity V2 rejects tautological @post (Q-602, exit 5)" 5 "[Q-602]" \
    verify "$WORK/trivial_post.ex" --out-dir "$WORK/o13"

# 14. ECHIDNA Mutation Engine V3: weak @post survives OperatorSwap mutant -> Q-603, exit 5
cat > "$WORK/weak_spec.ex" <<'EX'
defmodule WeakSpec do
  use Quintessence.Face, layer: :a
  @pre spec(x >= 10)
  @post spec(result >= 0)
  def increment(x), do: x + 1
end
EX
assert_case "14. ECHIDNA mutation engine catches weak @post (Q-603, exit 5)" 5 "[Q-603]" \
    verify "$WORK/weak_spec.ex" --out-dir "$WORK/o14"

# 15. Honest Trust-Level 5 batch kernel check when coqc/lean absent -> Q-504, exit 4
assert_case "15. Honest Level-5 batch kernel gate without Coq/Lean (Q-504, exit 4)" 4 "[Q-504]" \
    verify examples/quintessence --no-mutation --require-level-5 --out-dir "$WORK/o15"

echo "------------------------------------------------------------"
echo "Suite summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
