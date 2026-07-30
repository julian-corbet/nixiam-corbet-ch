# Experiments

Throwaway trials: spikes, one-off scripts, measurements not yet worth
writing up properly. Nothing here is guaranteed to work, be maintained, or
survive the next cleanup pass. If something in here turns out to matter,
distill the actual finding into [`../studies/`](../studies/README.md) and
let the experiment stay disposable (or delete it).

This is also the open-questions ledger for nixiam's own judgment calls —
every entry below corresponds to a default, an omission, or a design
asymmetry that's reasoned in a module's own comments but not measured or
exercised by any test. `nix flake check` (see the main
[README](../README.md)) proves both modules *evaluate*; it starts nothing,
binds no port, and performs no OIDC round trip. The one thing stronger
than that is the live production deployment the README mentions — but
that is a single anecdote ("it worked, end to end, once"), not a
reproducible measurement, so it closes none of the questions below on its
own.

All open; nothing has been run against these specifically — no host
in this repo's own test matrix exercises a missing-secret boot, a schema
version jump, an interface rename, or a v1→v2 upgrade under CI.

## 001 — no explicit `Restart=`/`RestartSec=`/`TimeoutStartSec=` tuning for either service

**Question:** neither `lldap.nix` nor `pocket-id.nix` sets any systemd
restart or timeout knob on `systemd.services.lldap` /
`systemd.services.pocket-id` — both inherit whatever `services.lldap` and
`services.pocket-id` set upstream in nixpkgs. Yet `lldap.nix`'s
`dependsOnUnits` option description explicitly reasons about a restart-loop
failure shape: *"turns 'lldap fails and restarts in a loop right after
every boot until secrets happen to show up' into 'lldap correctly waits
for secrets, then starts once'."* That sentence assumes upstream already
gives lldap a restart policy that loops (some `Restart=on-failure` or
equivalent) rather than giving up after N attempts (`StartLimitBurst`) —
has that upstream default actually been read/verified, or is the whole
recovery story reasoned from how systemd services conventionally behave?

**Hypothesis:** nixpkgs' `services.lldap`/`services.pocket-id` almost
certainly do set some restart policy (most nixpkgs service modules do),
so the "restarts in a loop" framing is probably accurate — but neither
module in this repo pins it, so a future nixpkgs change to either
upstream module's `Restart=`/`StartLimitIntervalSec=`/`StartLimitBurst=`
silently changes nixiam's own documented recovery behavior with nothing
here to catch it.

**Method sketch:** `nix eval` the composed `examples/host` system's
`systemd.services.lldap.serviceConfig` / `systemd.services.pocket-id.
serviceConfig` and read off whatever `Restart=`/`RestartSec=`/
`StartLimitBurst=` upstream actually sets; separately, on a real host,
delay `jwtSecretFile` from existing at boot and watch `systemctl status
lldap` / `journalctl -u lldap` to confirm the loop-then-recover shape the
comment describes actually happens rather than a give-up-after-N-tries
dead unit.

**Status:** open.

## 002 — `package` tracks nixpkgs with no guard against a schema-crossing version jump

**Question:** `lldap.nix`'s `package` option (default `pkgs.lldap`) carries
this warning: *"lldap's on-disk SQLite schema is versioned, and a version
jump can bump the schema; migrations are one-way. Pinning this to a
version older than the one that last wrote an existing database will fail
to open it (or, in some historical lldap releases, silently downgrade the
schema)."* The module deliberately ships no pinned/patched build (a prior
version of this module tried that and broke evaluation for days — see the
module header). But the plain-`pkgs.lldap` default means every ordinary
`flake.lock` bump that happens to cross a schema-breaking lldap release
changes the on-disk format with zero assertion, warning, or check in
either direction — nothing here compares "the lldap version this database
was last opened with" against "the lldap version about to open it."

**Hypothesis:** this is a real, currently-unmitigated gap, not just a
documentation caveat — the option description tells the *operator* to be
careful when pinning/restoring, but there is no code path (a stamped
version marker in `stateDir`, a boot-time check like
`exposeOnInterfaces`'s advisory script) that would catch an accidental
forward-then-back version straddle, or even just surface which schema
version is currently on disk.

**Method sketch:** find whether lldap writes any schema-version marker
into its own SQLite database (a `PRAGMA user_version`, a migrations
table) that a boot-time script analogous to `interfaceCheckScript` could
read and compare against the running binary's expected schema version,
logging (never failing, same non-fatal discipline as the interface check)
when they disagree.

**Status:** open.

## 003 — is the `exposeOnInterfaces` boot-time check ever actually exercised?

**Question:** `lldap.nix`'s `nixiam-lldap-interface-check` oneshot exists
specifically to catch the exact incident described in `exposeOnInterfaces`'s
own description — a VPN/mesh interface renamed during a migration, with
the firewall rule left silently referencing a name that no longer exists.
The check itself has never been run against that scenario (or any
scenario) inside this repo: no `nixosTest` starts a system, renames or
removes an interface, and asserts the warning appears in the journal.

**Hypothesis:** the script's logic (`ip link show <name>` against every
listed interface, log-only, never fatal) is simple enough to be low-risk,
but "simple enough to probably be right" is exactly the reasoning that
let the original incident go unnoticed for so long in the first place —
the whole point of writing this check was to stop relying on that kind of
confidence.

**Method sketch:** a `nixosTest` (or a manual run on the live production
host) that brings up a dummy interface, lists it in
`exposeOnInterfaces`, confirms silence; then removes the interface (or
never brings it up) and confirms the specific warning text appears in
`journalctl -u nixiam-lldap-interface-check`.

**Status:** open. (This is also the concrete instance of the README's own
"no automated `nixosTest`... beyond pure evaluation" gap, applied to one
specific piece of runtime behavior this module claims to provide.)

## 004 — pocket-id's v1→v2 legacy-database relocation script is untested automation around a production incident

**Question:** `pocket-id.nix`'s `ExecStartPre` (`nixiam-pocket-id-relocate-legacy-db`)
moves `${dataDir}/pocket-id.db` to `${dataDir}/data/pocket-id.db` exactly
once, guarded by `[ -f "$legacy" ] && [ ! -f "$v2" ]`. The module's own
`package` option description calls the failure it's guarding against a
"real pocket-id v1->v2 upgrade trap" found in production — but the fix
itself has no automated coverage. Open sub-questions the comments don't
address: does `ExecStartPre` run with permissions sufficient to `mv` a
file potentially owned by a *different* uid than the one about to run
pocket-id (relevant when `uid`/`gid` get pinned mid-migration, per those
options' own reasoning about cross-reimage ownership)? Is there a window
where `${dataDir}/data` doesn't exist yet (created by `mkdir -p` in the
same script, but is that ordered correctly relative to whatever creates
`dataDir` itself)?

**Hypothesis:** the script is short and the guard condition looks
sufficient for the single-instance, single-migration-event case it was
written for, but "found in production, fixed in production" is a
different level of evidence than a reproducible test — precisely the gap
the README calls out: *"no automated `nixosTest` starting lldap, binding
a port, or performing an OIDC round trip."*

**Method sketch:** a `nixosTest` that seeds a v1-shaped `dataDir` (a file
directly at `dataDir/pocket-id.db`), boots the composed system, and
asserts the file landed at `dataDir/data/pocket-id.db` with pocket-id's
own uid/gid as owner and the service actually reached `active`.

**Status:** open.

## 005 — asymmetry: `lldap.nix` has `dependsOnUnits`, `pocket-id.nix` has no equivalent for `encryptionKeyFile`

**Question:** `lldap.nix`'s `dependsOnUnits` exists specifically to avoid
"lldap fails and restarts in a loop right after every boot until secrets
happen to show up," wired into both `after` and `requires` for whatever
unit provisions `jwtSecretFile`/`adminPasswordFile`/`keySeedEnvFile`.
`pocket-id.nix`'s `encryptionKeyFile` is wired differently — via
`services.pocket-id.credentials.ENCRYPTION_KEY` (systemd `LoadCredential`)
rather than an `EnvironmentFile`/plain path read — and has no
`dependsOnUnits`-equivalent option at all. Is that omission deliberate
(does `LoadCredential`'s own systemd semantics already order correctly
against whatever provisions the credential source, making an explicit
`after`/`requires` redundant) or is it the same missing-secret race this
repo's sibling option exists to prevent, just not yet ported over?

**Hypothesis:** `LoadCredential=` sources from a path that must exist at
service activation the same way `EnvironmentFile=` does, so the same
race is plausible unless something else (a `systemd.services.pocket-id.
after`/`requires` this module doesn't set, relying on whatever the
consuming host's own configuration adds externally) already orders it.
Nothing in `pocket-id.nix` or its comments states which is true.

**Method sketch:** read nixpkgs' own `services.pocket-id` module for
whatever `after`/`requires`/`wants` it sets by default around
`LoadCredential`; if none, decide whether `pocket-id.nix` needs its own
`dependsOnUnits` option mirroring `lldap.nix`'s, or whether the asymmetry
is intentional and worth stating explicitly instead of leaving it silent.

**Status:** open.

## 006 — plain-LDAP-over-non-loopback has a documented risk but no runtime check, unlike the analogous `exposeOnInterfaces` case

**Question:** `ldapHost`'s description states plainly: *"lldap speaks
plain LDAP only on this listener... Binding beyond loopback without some
other layer of transport encryption already in front of it... means
directory contents and bind credentials cross the network in the clear."*
That is exactly the shape of risk `exposeOnInterfaces` gets a dedicated
boot-time advisory check for (a misconfiguration that's silent and
severe). But `ldapHost` itself gets no analogous check — nothing warns at
boot if `ldapHost` is set wide (e.g. `"0.0.0.0"`) with `exposeOnInterfaces`
left empty (the traffic-encryption risk exists independently of whether
the firewall opens the port to anything) or logs anything distinguishing
"wide bind, deliberately fronted by a proxy" from "wide bind, nothing in
front of it, by mistake."

**Hypothesis:** probably out of scope for a Nix module to detect at
build/boot time (unlike a named interface, "is something else terminating
TLS in front of this" isn't something `ip link show` or its equivalent
can check) — but that's a reasoned dismissal, not a decision that's
actually been weighed against, say, a boot-time warning whenever
`ldapHost != "127.0.0.1"` regardless of what's supposedly in front of it.

**Method sketch:** decide whether a cheap, always-non-fatal boot-time log
line ("ldapHost is set to a non-loopback address; make sure something is
terminating TLS in front of this — lldap itself has no LDAPS") is worth
adding, mirroring the discipline already applied to `exposeOnInterfaces`,
or whether that's judged noisy/unhelpful and the doc comment alone is
considered sufficient.

**Status:** open.

## 007 — `uid`/`gid` auto-allocation (`null` default) reproducibility across a reimage — reasoned identically for both modules, not verified for either

**Question:** both `lldap.nix` and `pocket-id.nix` default `uid`/`gid` to
`null` (auto-allocate), and `pocket-id.nix`'s own `uid` description is
explicit that this is reasoned by analogy, not shared code: *"Note this is
a DIFFERENT concern from `lldap.nix`'s own `uid` option in this repo...
even though the fix (pin a number) looks the same."* Neither module's
reasoning about uid-allocation non-reproducibility across a fresh
install/reimage (NixOS's allocation bookkeeping being "stable across
rebuilds of an EXISTING host... but not guaranteed to reproduce the same
number on a genuinely fresh install... onto a new disk or image") has
been checked against an actual reimage — it's inferred from how NixOS's
allocator is documented/known to behave in general, not from reimaging a
host running either service and comparing the allocated uid before and
after.

**Hypothesis:** the reasoning matches NixOS's well-known
`ids.uids`/dynamic-allocation behavior closely enough to be trustworthy,
but "closely enough by analogy" is the same category of reasoning that
produced the lldap `DynamicUser` incident `lldap.nix`'s header describes
in detail (a real failure that surfaced far from its actual cause) — so
it's flagged rather than assumed safe.

**Method sketch:** reimage a throwaway host twice from the identical
`examples/host`-style configuration with `uid`/`gid` left `null` for both
services, and diff the two runs' allocated uid/gid numbers for `lldap`
and `pocket-id`.

**Status:** open.

## 008 — is `darwinModules.posix` actually usable, or just a plausible-looking alias?

**Question:** `flake.nix` exposes `darwinModules.posix` pointing at the
same `modules/posix.nix` file used for `nixosModules`/`systemManagerModules`,
on the reasoning that the module only uses bare `options`/`config.assertions`
primitives common to every module system built on `lib.evalModules`. This
repo pulls in no `nix-darwin` input and has no check that actually composes
the module into a `darwinConfiguration` the way `checks/default.nix` does
for the other two backends — the alias is a reasoned guess, not a proven
one, the exact gap a sibling pure-data repo's own experiment 001 flags for
the same shape of claim.

**Hypothesis:** nix-darwin's module system is close enough to NixOS's own
(both are `lib.evalModules` underneath) that a module this simple — no
`pkgs`, no `systemd`, no platform-specific option namespace referenced —
composes without incident. This is the first real consumer of this claim
that matters in practice: the Mac here is the one machine
nixiam's original lldap/pocket-id design never had to answer for, since
those two modules ship no `darwinModules` output at all (see README's
"What this deliberately does not do").

**Method sketch:** add `nix-darwin` as a `checks`-only input (the same
"used by checks only" posture `system-manager` already has in this flake),
build a minimal `darwinConfiguration` composing `darwinModules.posix` with
a small fixture, and add it to the backend-parity checks alongside the
existing NixOS/system-manager pair.

**Status:** open.

## 009 — the `groups`/`reconcile` half of the registry has no real consumer inside this repo's own tests yet

**Question:** `groups` and `identities.<name>.reconcile` both exist because
a sibling module elsewhere (nixstorage's reconciler) is meant to read them
and act on them — but that consumer lives in a different repo, and this
repo's own `checks/` only proves the registry's *shape* (the values are
readable, correctly typed, and collision-free), never that a real
reconciler actually behaves correctly against them. The same gap existed
back when this module lived in the standalone nixposix repo, unclosed then
and still unclosed now that it has folded back into nixiam.

**Hypothesis:** the shape is stable enough (nixstorage's own
`modules/reconciler.nix` already reads `config.nixiam.posix.groups`/
`.identities`/`.podSecurity` defensively today — see this repo's own
README) that the actual reconciliation logic is unaffected by which repo
the registry lives in. Unverified until nixstorage's own checks are
re-run against a fixture pointed at this repo.

**Method sketch:** re-run nixstorage's own `checks/` against a fixture
that imports `nixiam.nixosModules.posix` and confirm nothing in its
reconciler-level behavior changed from when it imported the standalone
nixposix repo, or from when posix.nix lived inside nixid before that.

**Status:** open.

## 010 — `identities`/`groups` untested at anything near real scale

**Question:** every fixture in `checks/default.nix` declares two or three
identities. The uid/gid-collision detection (`duplicatesOf`) is an
`attrNames`/`foldl'` pass over `cfg.identities`, which is the ordinary Nix
idiom for this shape of data — but nothing here measures `nix flake
check`'s eval time against a fixture anywhere near the dozens-to-low-
hundreds of identities a real multi-host, multi-app deployment accumulates over
time.

**Hypothesis:** attribute-set folds over a few hundred entries are not a
real eval-time concern for nixpkgs-scale evaluations in general, but that
is an assumption carried over unchanged across every home this module has
had, not a benchmark taken against this module specifically.

**Method sketch:** generate a synthetic fixture with a few hundred
`identities` entries (`builtins.genList`-built, never committed as a real
inventory — this repo ships schema, not data, the same rule nixhost's own
`lib/hosts.nix` states for its host tree) and time `nix eval` against the
`podSecurity` default and the collision assertions on it.

**Status:** open.

## 011 — only two `variant` shapes exist; is a third runtime shape waiting to be found?

**Question:** `mkPodSecurityFor` branches on exactly two values —
`"native"` and `"puid"` — covering "runs as its target uid from the first
instruction" and "starts root, drops privilege via PUID/PGID" respectively.
Both were reasoned from container images actually encountered. Whether a
third shape exists in practice (an image that needs supplementary GROUPS
plural rather than one `fsGroup`, say, or one that drops privilege via a
mechanism that is neither of these two) has not been surveyed against a
real, growing app inventory since this module's original design.

**Hypothesis:** two variants have covered every real identity declared so
far, but "every one encountered so far" is exactly the kind of confidence
this family's own testing discipline treats as provisional, not proof
there is no third shape waiting in the next app onboarded.

**Method sketch:** when an app's container image resists both `"native"`
and `"puid"` handling, work out the actual shape it needs, decide whether
it is a genuinely new `variant` value or better modeled as an option on
the existing two, and land it with a fixture and an assertion covering the
distinction — not silently reused as a near-fit for one of the existing two.

**Status:** open.

## Renumbering history

001–007 above are original to this file, from nixid's own
`experiments/README.md`. 008–011 were originally numbered 001–004 in the
standalone nixposix repo's own `experiments/README.md`; they are
renumbered here, unchanged in content beyond namespace (`nixposix.*` →
`nixiam.posix.*`) and repo references, when that repo folded back into
this one as `nixiam.posix` (see the main [README](../README.md)'s "Why
posix folded back in" for the argument).
