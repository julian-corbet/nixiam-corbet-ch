#!/usr/bin/env bash
# experiments/run-lldap-reconcile-proof.sh
#
# Runs the REAL, unmodified nixiam-lldap-reconcile script this repo ships (built from
# modules/lldap-reconcile.nix via lldap-reconcile-harness.nix) against
# experiments/mock-lldap.py -- a local, throwaway stand-in for lldap's HTTP API, never a live
# lldap -- and proves, by actually executing it rather than reading it, the two properties this
# module's own header claims:
#
#   1. IDEMPOTENCY: running the script twice against the same state performs the mutations
#      exactly once; the second run performs ZERO mutation calls.
#   2. THE DELETION-REFUSAL DECISION, in both directions: an undeclared user
#      ("mallory", seeded directly into the mock, never mentioned in the Nix declaration at all)
#      is reported and left alone across every run; a user declared with `enable = false` AND a
#      set `acknowledgeRemoval` ("carol") IS deleted -- the one, explicitly opt-in path that does.
#      An undeclared EXTRA group membership on an otherwise-declared user (bob, pre-seeded as
#      already a member of a group his declaration never mentions) is reported and left alone too.
#
# Nothing here touches a live lldap -- mock-lldap.py is a ~150-line local Python stand-in, started
# and torn down entirely within this script's own run, on loopback only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nixiam-lldap-reconcile-proof.XXXXXX")"
trap 'kill "$MOCK_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== workdir: $WORK"

CREDFILE="$WORK/admin-password"
printf 'test-admin-password' > "$CREDFILE"

# ── start the mock, on loopback, on whatever port the OS hands it ──────────────────────────────
python3 "$REPO_ROOT/experiments/mock-lldap.py" > "$WORK/mock.out" 2>&1 &
MOCK_PID=$!

PORT=""
for _ in $(seq 1 50); do
  if grep -q '^MOCK_LLDAP_PORT=' "$WORK/mock.out" 2>/dev/null; then
    PORT="$(grep '^MOCK_LLDAP_PORT=' "$WORK/mock.out" | head -1 | cut -d= -f2)"
    break
  fi
  sleep 0.1
done
[ -n "$PORT" ] || { echo "FAIL: mock-lldap.py never printed a port"; exit 1; }
API="http://127.0.0.1:$PORT"
echo "== mock lldap listening on $API (pid $MOCK_PID)"

# ── pre-seed: bob and carol already exist; "mallory" is undeclared drift; bob already belongs
# to a group his declaration never mentions (undeclared-membership drift on a declared user) ────
curl -fsS -X POST "$API/_seed" -H 'Content-Type: application/json' -d '{
  "users": {
    "bob":     {"id":"bob",     "displayName":"Bob Example (seed)",     "email":"bob@example.com",     "groups":["extra-legacy-group"]},
    "carol":   {"id":"carol",   "displayName":"Carol Example (seed)",   "email":"carol@example.com",   "groups":[]},
    "mallory": {"id":"mallory", "displayName":"Mallory Undeclared",     "email":"mallory@example.com", "groups":[]}
  },
  "groups": { "extra-legacy-group": {"id": 1} },
  "next_group_id": 2
}' > /dev/null
echo "== seeded: bob (pre-existing, extra undeclared membership), carol (to be pruned), mallory (undeclared drift)"

# ── build the REAL reconcile script from modules/lldap-reconcile.nix, pointed at the mock ──────
echo "== building nixiam-lldap-reconcile from modules/lldap-reconcile.nix ..."
nix build --impure --no-link --print-out-paths \
  --file "$REPO_ROOT/experiments/lldap-reconcile-harness.nix" \
  --argstr apiUrl "$API" \
  --argstr credentialFile "$CREDFILE" \
  > "$WORK/build-out" 2>"$WORK/build-err" \
  || { echo "FAIL: nix build failed:"; cat "$WORK/build-err"; exit 1; }
SCRIPT="$(cat "$WORK/build-out")/bin/nixiam-lldap-reconcile"
[ -x "$SCRIPT" ] || { echo "FAIL: built script not found/executable at $SCRIPT"; exit 1; }
echo "== built: $SCRIPT"

fail=0

echo
echo "── RUN 1 (fresh state: alice absent, bob missing his declared group, carol pending prune) ──"
run1_status=0
"$SCRIPT" > "$WORK/run1.out" 2>&1 || run1_status=$?
sed 's/^/   /' "$WORK/run1.out"
echo "   exit status: $run1_status"

curl -fsS "$API/_calls" -o "$WORK/calls1.json"
curl -fsS "$API/_state" -o "$WORK/state1.json"

echo
echo "-- run 1 mutation calls:"
jq -c '.[]' "$WORK/calls1.json" | sed 's/^/   /'

expect_call() {
  local desc="$1" filter="$2"
  if jq -e "$filter" "$WORK/calls1.json" > /dev/null; then
    echo "   PASS: $desc"
  else
    echo "   FAIL: $desc"
    fail=1
  fi
}

expect_call "created missing user 'alice'" \
  'any(.[]; .op=="createUser" and .id=="alice")'
expect_call "created missing group 'admins' (alice's declared membership)" \
  'any(.[]; .op=="createGroup" and .name=="admins")'
expect_call "created missing group 'readers' (bob's declared membership)" \
  'any(.[]; .op=="createGroup" and .name=="readers")'
expect_call "added alice to 'admins'" \
  'any(.[]; .op=="addUserToGroup" and .user=="alice" and .group=="admins")'
expect_call "added bob to 'readers'" \
  'any(.[]; .op=="addUserToGroup" and .user=="bob" and .group=="readers")'
expect_call "deleted 'carol' (enable=false, acknowledgeRemoval set)" \
  'any(.[]; .op=="deleteUser" and .id=="carol")'
expect_call "NEVER deleted 'mallory' (undeclared, no acknowledgeRemoval)" \
  'all(.[]; .op!="deleteUser" or .id!="mallory")'

if jq -e '.users | has("mallory")' "$WORK/state1.json" > /dev/null; then
  echo "   PASS: mallory still present in mock state after run 1 (undeclared drift, never removed)"
else
  echo "   FAIL: mallory was removed from mock state -- deletion-refusal violated"
  fail=1
fi

if jq -e '.users | has("carol") | not' "$WORK/state1.json" > /dev/null; then
  echo "   PASS: carol actually removed from mock state (the one acknowledged prune)"
else
  echo "   FAIL: carol still present -- the opt-in prune path did not fire"
  fail=1
fi

if [ "$run1_status" -ne 0 ]; then
  echo "   PASS: run 1 exited non-zero (drift was present: mallory, bob's extra membership)"
else
  echo "   FAIL: run 1 exited 0 despite real drift being present"
  fail=1
fi

if grep -q "user 'mallory' is not declared" "$WORK/run1.out"; then
  echo "   PASS: run 1 logged a WARN naming mallory specifically"
else
  echo "   FAIL: no WARN log line naming mallory"
  fail=1
fi

if grep -q "member of group 'extra-legacy-group'" "$WORK/run1.out"; then
  echo "   PASS: run 1 logged a WARN about bob's undeclared extra membership, without removing it"
else
  echo "   FAIL: no WARN log line about bob's undeclared extra-legacy-group membership"
  fail=1
fi

echo
echo "── reset call log (state untouched), RUN 2 (idempotency proof) ─────────────────────────────"
curl -fsS -X POST "$API/_reset_calls" > /dev/null

run2_status=0
"$SCRIPT" > "$WORK/run2.out" 2>&1 || run2_status=$?
sed 's/^/   /' "$WORK/run2.out"
echo "   exit status: $run2_status"

curl -fsS "$API/_calls" -o "$WORK/calls2.json"
n_calls_run2="$(jq 'length' "$WORK/calls2.json")"

if [ "$n_calls_run2" -eq 0 ]; then
  echo "   PASS: run 2 performed ZERO mutation calls (idempotent) -- $(jq -c '.' "$WORK/calls2.json")"
else
  echo "   FAIL: run 2 performed $n_calls_run2 mutation call(s), expected 0:"
  jq -c '.[]' "$WORK/calls2.json" | sed 's/^/     /'
  fail=1
fi

if [ "$run2_status" -eq "$run1_status" ] && [ "$run2_status" -ne 0 ]; then
  echo "   PASS: run 2 still exits non-zero (mallory/bob's extra membership are still undeclared -- reported every tick, by design)"
else
  echo "   FAIL: run 2 exit status ($run2_status) does not match the still-present-drift expectation"
  fail=1
fi

curl -fsS "$API/_state" -o "$WORK/state2.json"
if jq -e '.users | has("mallory")' "$WORK/state2.json" > /dev/null; then
  echo "   PASS: mallory STILL present after run 2 (deletion-refusal holds across repeated runs, not just once)"
else
  echo "   FAIL: mallory disappeared by run 2"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
else
  echo "ONE OR MORE CHECKS FAILED"
  exit 1
fi
