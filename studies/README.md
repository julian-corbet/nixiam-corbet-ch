# studies

Written-up findings: things that were tried in
[`../experiments/`](../experiments/README.md), worked (or failed
instructively), and are worth recording properly — with the reasoning,
not just the result.

A study earns its place here once it changed a decision in the main
project. `nix flake check`'s `modules-evaluate` check (see the main
[README](../README.md)) proves every module *evaluates* — it composes
them into one system, forces every option's default and every
`throw`-guarded required value, and fails by name if either breaks — but
it starts no daemon, binds no port, and performs no OIDC round trip.
Nothing stronger than pure evaluation has been run *inside this repo's
own test matrix*, with the one exception below.

## `nixiam-lldap-reconcile` idempotency and deletion-refusal, actually executed (2026-07-30)

Closes [experiment 012](../experiments/README.md#012--lldap-reconcile-idempotency--deletion-refusal-executed-against-a-local-mock).
`modules/lldap-reconcile.nix`'s own header makes two claims about its generated script that pure
`nix flake check` evaluation cannot prove: running it twice against unchanged state is a no-op
(zero mutation calls the second time), and an lldap user/membership `nixiam.users` does not
declare is reported but never removed, except through the one explicit,
per-person `acknowledgeRemoval` opt-in.

Both were proven by actually running the REAL, unmodified script this repo ships —
`experiments/lldap-reconcile-harness.nix` builds it straight from `modules/lldap-reconcile.nix`,
not a reimplementation — against `experiments/mock-lldap.py`, a small local stand-in for lldap's
own two HTTP endpoints (`/auth/simple/login`, `/api/graphql`), implementing exactly the
query/mutation shapes the script calls (learned from lldap's own upstream `schema.graphql` +
`scripts/bootstrap.sh`; see `lldap-reconcile.nix`'s header for the precise citations). Never a
live lldap: the mock runs on loopback, started and torn down entirely within
`experiments/run-lldap-reconcile-proof.sh`'s own invocation.

**Fixture:** alice (wholly absent from the mock), bob (already exists, missing his one declared
group membership, and already belongs to a group his declaration never mentions), carol
(`enable = false` + `acknowledgeRemoval` set, already exists — the one case that should be
deleted), and mallory (seeded directly into the mock, never declared in `nixiam.users` at all —
plain undeclared drift).

**Run 1** (fresh state) performed exactly the six expected mutations — created group `admins`,
created group `readers`, created user `alice`, added alice→admins, added bob→readers, deleted
carol — logged a `WARN` naming mallory and a separate `WARN` about bob's undeclared
`extra-legacy-group` membership, touched neither, and exited non-zero (drift present, reported
loudly, exactly as `lldap-reconcile.nix`'s header specifies).

**Run 2** (same mock, call log reset, state otherwise untouched) performed **zero** mutation
calls — `jq 'length'` on the mock's own `/_calls` log came back `0` — and still exited non-zero,
because mallory and bob's extra membership are still undeclared and are reported on *every* tick
by design, not just once. Mallory was still present in the mock's state after both runs; carol
was gone after run 1 and stayed gone. Full transcript (abbreviated, ordering as actually
produced):

```
── RUN 1 ──
nixiam-lldap-reconcile: created missing group 'admins'
nixiam-lldap-reconcile: created missing group 'readers'
nixiam-lldap-reconcile: created missing user 'alice'
nixiam-lldap-reconcile: added 'alice' to group 'admins'
nixiam-lldap-reconcile: added 'bob' to group 'readers'
nixiam-lldap-reconcile: WARN: lldap user 'bob' is a member of group 'extra-legacy-group', which
  nixiam.users."bob".groups does not declare -- left untouched
nixiam-lldap-reconcile: deleted acknowledged-removal user 'carol' (nixiam.users."carol".enable =
  false, acknowledgeRemoval set)
nixiam-lldap-reconcile: WARN: lldap user 'mallory' is not declared in nixiam.users ... -- left
  untouched
nixiam-lldap-reconcile: reconcile finished WITH drift or errors reported above
exit status: 1

── RUN 2 (call log reset first) ──
nixiam-lldap-reconcile: WARN: lldap user 'bob' is a member of group 'extra-legacy-group' ...
nixiam-lldap-reconcile: WARN: lldap user 'mallory' is not declared ...
nixiam-lldap-reconcile: reconcile finished WITH drift or errors reported above
exit status: 1
-- mutation calls this run: []
```

**What this does NOT close:** a mock is not lldap. `experiments/README.md` #013–#015 name the
three specific things this run cannot speak to — whether a narrower built-in lldap group than
full admin actually authorizes these four mutations, `deleteUser`'s real cascade effect on group
membership, and concurrent-tick races against lldap's own database layer — each unverified
against a real instance, same honesty this repo already holds `lldap.nix`/`pocket-id.nix` to for
their own unverified claims (experiments 001–007).

The README's "Status" section also notes both modules are running in a
real, separate production deployment, and that "the identity chain behind
that deployment's mail stack has been verified end to end." That is a
genuine real-world data point, not a fabrication — but it is a single
anecdote (login worked, once, on one host) rather than a reproducible
measurement with numbers attached, so it does not resolve any of the
specific questions in `../experiments/README.md` (which version of lldap,
what restart behavior a missing secret actually produced, whether the
`exposeOnInterfaces` check has ever fired, whether the v1→v2 relocation
script has ever actually run against real v1 data on that host). If any
of that gets instrumented and written up with actual output attached, it
belongs here.

Nothing invented below — this is a list of what would be worth measuring,
taken directly from `../experiments/README.md`'s open questions, not a
result:

- **Upstream restart/timeout behavior for `systemd.services.lldap` /
  `systemd.services.pocket-id`** (experiment 001) — read the actual
  `Restart=`/`RestartSec=`/`StartLimitBurst=` nixpkgs sets today, and
  confirm on a real host that a missing secret at boot produces the
  loop-then-recover shape `dependsOnUnits`'s description assumes, not a
  give-up-after-N-tries dead unit.
- **lldap SQLite schema-version exposure** (experiment 002) — whether
  lldap stamps a readable schema version into its own database that a
  boot-time check could compare against the running binary, before any
  `flake.lock` bump accidentally crosses a schema-breaking release.
- **`exposeOnInterfaces` check firing correctly** (experiment 003) — an
  actual run (test or manual) that renames/removes a listed interface and
  confirms the warning text appears in the journal, the one behavior this
  module was written specifically to provide.
- **v1→v2 pocket-id database relocation, exercised end to end**
  (experiment 004) — seed a v1-shaped `dataDir`, boot, and confirm the
  file lands correctly with the right ownership and the service reaches
  `active`, rather than relying on "it worked once in production."
- **`uid`/`gid` auto-allocation reproducibility across a reimage**
  (experiment 007) — reimage the same configuration twice and diff the
  allocated uid/gid numbers for both services.
- **`darwinModules.posix` proven against a real nix-darwin eval**
  (experiment 008) — once a `nix-darwin` input and a composed
  `darwinConfiguration` exist in `checks/`, the finding (parity confirmed,
  or a genuine incompatibility found and fixed) belongs here.
- **nixstorage's reconciler re-verified against `nixiam.posix`**
  (experiment 009) — whether its existing checks passed unchanged or
  needed a fix, across each home this registry has had (inside nixid,
  standalone as nixposix, and folded back into nixiam).
- **Eval-time at real scale** (experiment 010) — actual timing
  against a synthetic few-hundred-identity fixture, not an assumption
  that attribute-set folds "should" scale fine.
- **A third `variant` shape, if one is ever found** (experiment 011) —
  the concrete container image that needed it, and why neither `"native"`
  nor `"puid"` fit.

None of these have been run. Until one is, this directory stays empty of
findings by design — see `../experiments/README.md` for the reasoning
behind each default in the meantime.
