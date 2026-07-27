# studies

Written-up findings: things that were tried in
[`../experiments/`](../experiments/README.md), worked (or failed
instructively), and are worth recording properly — with the reasoning,
not just the result.

A study earns its place here once it changed a decision in the main
project. Nothing has closed yet. `nix flake check`'s `modules-evaluate`
check (see the main [README](../README.md)) proves both modules
*evaluate* — it composes them into one system, forces every option's
default and every `throw`-guarded required value, and fails by name if
either breaks — but it starts no daemon, binds no port, and performs no
OIDC round trip. Nothing stronger than that has been run *inside this
repo's own test matrix*.

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

None of these have been run. Until one is, this directory stays empty of
findings by design — see `../experiments/README.md` for the reasoning
behind each default in the meantime.
