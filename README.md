# nixid

Two independent things, packaged as three NixOS modules under one flake:

1. **An identity-provider stack** for a self-hosted deployment: an LDAP
   directory ([lldap](https://github.com/lldap/lldap)) and the OIDC/SSO
   provider ([pocket-id](https://github.com/pocket-id/pocket-id)) that sits
   in front of it. This is "identity" in the everyday sense — a human's
   login and the directory that remembers it.
2. **A fleet-wide POSIX uid/gid registry** (`posix.nix`) — pure data, no
   daemon, no process, nothing that ever starts. This is "identity" in a
   completely different, POSIX sense — which number a host or container
   runs as — with no relationship to (1) beyond sharing this repository
   and the `nixid.*` option prefix.

Those two meanings of "identity" colliding under one name is exactly why
this README has a dedicated section, below, arguing why that is still the
right shape rather than something that crept in by accident. Read
["Two scopes, one repo"](#two-scopes-one-repo) if the cohabitation looks
wrong at first glance — it was reasoned about deliberately, not assumed.

**Status: alpha.** All three modules are extracted, wired into `flake.nix`,
and checked in CI. Two independent `nix flake check` groups exist for two
independent reasons:

- `modules-evaluate` composes all three into one NixOS system from
  [examples/host](examples/host), which exercises every assertion any
  module makes and — because all three live under `nixid.*` — is the only
  thing that can catch a collision between them. Proven in the failing
  direction too: removing a required credential path or mistyping a value
  fails the check by name.
- `posix-purity` is a different kind of check: not "do the modules
  evaluate" but "does `posix.nix` keep the promise its own header makes."
  It composes `nixosModules.posix` **alone** (see
  [examples/registry-only-host](examples/registry-only-host)) and fails if
  that ever produces a new systemd unit, a new `environment.systemPackages`
  entry, or if the module's own function ever grows a `pkgs` argument. See
  `checks/default.nix`'s own header for exactly what it proves and how it
  proves the proof itself isn't vacuous.

Both lldap and pocket-id are also running live in a real production
deployment (a small single-node host, outside this repo), and the identity
chain behind that deployment's mail stack has been verified end to end.
That remains the stronger evidence for those two modules — the
`modules-evaluate` check establishes that they evaluate, not that a login
succeeds. There is still no automated `nixosTest` starting lldap, binding
a port, or performing an OIDC round trip. `posix.nix` has no equivalent
live deployment yet; its own guarantee (never running anything at all) is
instead the kind of thing an eval-level check can prove completely, which
is what `posix-purity` does.

## Scope

Identity — the human/login kind — is its own concern, not a feature of any
one consumer. This repo exists specifically because a mail stack is only
ONE of several things that authenticate against an identity directory — a
self-hosted git forge and a Kubernetes dashboard are two more, equally
valid, equally unrelated to mail. Bundling `lldap`/`pocket-id` inside a
mail-transport repo would have made every non-mail consumer depend on a
package whose name and scope had nothing to do with what they actually
needed. See [nixmail](https://github.com/julian-corbet/nixmail-corbet-ch)'s
own README for the mirror image of this decision: it deliberately ships no
directory server or SSO provider and says so, pointing here instead.

This repo, in turn, ships no mail transport, no webmail, and no
mail-specific LDAP schema (which groups/attributes a mail server expects
to find in the directory) — that's `nixmail`'s `stalwart.nix` `ldap.*`
options, or whatever else you point at this directory. The identity-
provider stack only ever runs the directory server and the identity
provider in front of it.

The POSIX registry (`posix.nix`) has a completely separate scope, argued
in full in its own module header and in
["Two scopes, one repo"](#two-scopes-one-repo) below: a fleet-wide table of
"this name is uid N, gid M" and the Kubernetes `securityContext` it
implies, consumed by a sibling dataset-shape repo
([nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch)) and
by Kubernetes tenancy manifests — never the other way around.

## What this is

- **`lldap.nix`** — the LDAP directory itself: the user/group store every
  other service authenticates against, with its own small admin web
  UI/API. Manages the SERVER only (process, listeners, systemd unit) —
  it deliberately exposes no options for declaring users, groups, or
  passwords. Those are live data, not configuration; provision them
  through lldap's own admin UI/API or a restore from backup. See the
  module's own header comment for the real production incident behind
  its static-uid requirement, and for lldap's own attribute-name
  lowercasing behavior (a trap for anything that reads from it
  case-sensitively).
- **`pocket-id.nix`** — the OIDC/SSO identity provider in front of that
  directory: what a relying-party application actually redirects a user
  to for login. Manages the pocket-id PROCESS (how it starts, its
  listener, its encryption-key credential, a pinned uid/gid for stable
  ownership of persisted data) — and nothing about how it talks to the
  directory. See "What this deliberately does not do" below; it is the
  single most important thing to understand about this module.
- **`posix.nix`** — the fleet-wide POSIX identity registry: a table of
  `identities.<name> = { uid; gid; variant; ... }` and, generated straight
  from it, `podSecurity.<name>` — the Kubernetes `securityContext` each
  identity implies. PURE DATA: no `systemd.services`, no
  `environment.systemPackages`, not even a `pkgs` argument. Nothing this
  module declares ever runs, writes a file, or touches `/etc/passwd` — see
  the module's own header for the full reasoning and
  `checks/default.nix`'s `posix-purity` group for where that promise is
  mechanically enforced. This is the one module in this repo with no
  connection to LDAP, OIDC, or human login at all.

Both `lldap.nix` and `pocket-id.nix` are named after the real upstream
project behind them, not an abstract role ("ldap-directory",
"oidc-provider") — a generic interface with exactly one implementation
behind it documents a boundary that doesn't exist. If a second directory
or SSO backend is ever added here, it gets its own module. `posix.nix` is
named after what it IS (a POSIX identity registry) for the same reason,
one level removed: there is no upstream project standing behind a fleet's
own uid/gid convention to name it after.

## Two scopes, one repo

`posix.nix`'s own header spends its entire opening argument on why it must
stay cheap to import — cheap enough for "a single-purpose,
memory-hardened VPS running at ~1 GB of RAM with nothing to spare for a
service it doesn't need." The same repository also ships two real,
running services with real persisted state. Read literally, those two
facts pull in opposite directions, and this section exists to say plainly
why the arrangement is kept anyway, rather than just doing it.

**The two options actually on the table:**

1. **Distinct flake outputs, one repo (what this repo does).** Three
   separate `nixosModules` (`lldap`, `"pocket-id"`, `posix`), each backed
   by its own file, none importing either of the others. A consumer that
   writes `imports = [ inputs.nixid.nixosModules.posix ]` evaluates
   exactly `modules/posix.nix` and nothing else in this repository — no
   line of `lldap.nix` or `pocket-id.nix` is ever parsed, evaluated, or
   built as a result. `checks/default.nix`'s `posix-purity` group proves
   this mechanically rather than leaving it as an implication of "well,
   Nix modules are just files."
2. **A genuine split**: `posix.nix` moves to its own repository, with its
   own flake, its own `nix flake check`, no connection to lldap/pocket-id
   at all beyond a design-document ancestry. This repo's sibling
   [nixhardware](https://github.com/julian-corbet/nixhardware-corbet-ch)
   is the existing precedent for exactly this shape in this same family: a
   dedicated repo holding nothing but a pure-data registry
   (`modules/machines.nix`) and the derivations that read it, with no
   service anywhere in it. If this repo were being designed from scratch
   today, knowing that precedent, `posix.nix` would very plausibly start
   life there instead.

**Why (1), not (2), right now:**

The property `posix.nix`'s header actually needs — that importing it costs
a host nothing — is a property of **Nix module granularity**, not of
**git repository granularity**. A flake's `nixosModules.*` outputs are
individually-evaluated files; nothing about sharing a `flake.nix` or a
`.git` history with two unrelated services forces a third module to pay
for either of them. The literal cost the header is protecting against —
extra systemd units, extra packages, extra `pkgs` — is an eval/build-time
cost, and that cost is already, verifiably, zero: see
`checks/default.nix`'s `posix-purity` group, which composes
`nixosModules.posix` alone and asserts the resulting system has exactly
the same `systemd.services` and `environment.systemPackages` as one
without it. A host fetching this flake as an input does pay for the bytes
of `lldap.nix`/`pocket-id.nix` sitting in its git history, once, on disk —
but that is a one-time source-text checkout, not the recurring
RAM/build/generation cost the header is actually written to prevent.

Weighed against that, a genuine split has a real, immediate cost that a
mechanical-purity check cannot substitute for: this repo already has a
**published, cross-repo contract** depending on today's shape.
[nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch)'s own
`flake.nix` takes `nixid` as a flake input pinned to
`github:julian-corbet/nixid-corbet-ch` and imports
`nixid.nixosModules.posix` by that exact path — its reconciler module
resolves every `owner`/`group`/`identity` reference against
`config.nixid.posix.identities`/`.groups`/`.podSecurity`, with assertions
that name this exact option path in their own error messages. Moving
`posix.nix` to a new repository today, in this pass, would break that
contract immediately, with no coordinated update to `nixstorage` landing
in the same change — an uncoordinated breaking change to a real
dependent, not a cleanup. (This family is young enough that breaking an
option surface is an accepted cost when it buys something — see this
module's own header history — but breaking it *for no immediate reader
benefit, and without the matching update landing alongside it*, is a
different thing entirely: a dependent left broken, not a design improved.)

**The honest summary:** option (1) is not merely the cheap option chosen
to avoid work — it is *sufficient*, because the guarantee that actually
matters (zero eval/build cost to import the registry alone) is already
true and now mechanically checked, and the thing option (2) would improve
(discoverability — a reader finding `posix.nix` by way of a repo whose
name and top-level description are about LDAP and OIDC) is real but
smaller than the cost of breaking an already-published dependent with no
coordinated fix in hand. If a future pass lands a coordinated update
across this repo and `nixstorage` (and any other consumer of
`nixid.nixosModules.posix`), following the `nixhardware` precedent for
where the registry ends up is the right call at that point — this section
should be revisited then, not treated as a permanent verdict.

## What this deliberately does not do

**pocket-id's LDAP-sync wiring — which directory it binds to, the bind DN
and bind password, the search base and filter, and the attribute mapping
from directory entries onto pocket-id's own user fields — is configured
entirely out-of-band, through pocket-id's own admin UI/API, and stored
encrypted inside pocket-id's own database. It is not Nix-declarable
today**, and `pocket-id.nix` has no options for it: an `ldapSync.*` option
surface here would describe a Nix-side value pocket-id itself never reads
at start time. `pocket-id.nix`'s `encryptionKeyFile` is the key that
protects that stored configuration (the bind password, any SMTP password
entered the same way) at rest — this module wires the key in; it does not
and cannot push the sync configuration itself.

This is a real, permanent boundary in what pocket-id exposes as
declarative configuration versus runtime state — not a piece of
extraction work still queued. Wire the LDAP sync up once, by hand,
through the running pocket-id instance's own setup flow, exactly as you
would on a system this repo had no part in configuring at all. Contrast
this with `lldap.nix`'s own DIRECTORY-SCHEMA point (which group DNs and
attribute names a consumer expects to find), which genuinely is
Nix-declarable and belongs in whichever module consumes the directory —
a materially different kind of "not shipped here" than pocket-id's.

Also out of scope, same reasoning as `nixmail`'s own equivalent section:

- **A real NixOS VM test** (`nixosTest`) exercising both service modules
  against actual service startup, beyond pure evaluation. Not started.
- **`systemManagerModules`** — not evaluated for this repo. `pocket-id.nix`
  in particular touches `users.users`/credentials primitives that may or
  may not map cleanly onto `system-manager`'s smaller surface. Unassessed,
  not attempted. `posix.nix` has no such barrier — it is pure data with no
  `pkgs` argument at all — but nobody has added a `systemManagerModules`
  output for it either, since no consumer has asked for one yet.

## Quickstart

```nix
{
  inputs.nixid.url = "github:<owner>/<repo>"; # no public remote yet

  # host configuration.nix:
  imports = [
    inputs.nixid.nixosModules.lldap
    inputs.nixid.nixosModules."pocket-id"
  ];

  nixid.lldap = {
    enable = true;
    domain = "example.org";                       # placeholder — your real domain
    jwtSecretFile = "/run/secrets/lldap-jwt";
    adminPasswordFile = "/run/secrets/lldap-admin";
    keySeedEnvFile = "/run/secrets/lldap-seed";
  };

  nixid.pocketId = {
    enable = true;
    publicUrl = "https://id.example.org";
    encryptionKeyFile = "/run/secrets/pocket-id-encryption-key";
  };

  # Then, once, through the running pocket-id instance's own admin UI:
  # point its LDAP sync at ldap://127.0.0.1:389 / the baseDn above, with a
  # bind DN and password of your choosing. Not a step this flake can do
  # for you — see "What this deliberately does not do".
}
```

A host that wants **only** the POSIX registry — no LDAP directory, no
OIDC/SSO provider, nothing that runs — imports a single, different module
and nothing above it applies at all. See
[examples/registry-only-host](examples/registry-only-host) for the full
worked version this repo's own `posix-purity` check runs against:

```nix
{
  inputs.nixid.url = "github:<owner>/<repo>";

  imports = [ inputs.nixid.nixosModules.posix ];

  nixid.posix = {
    enable = true;
    domain = "example.org";
    identities.myapp.uid = 3000;   # gid defaults to a User Private Group
  };

  # config.nixid.posix.identities.myapp.uid          -> 3000, for a ZFS chown
  # config.nixid.posix.podSecurity.myapp.pod.runAsUser -> 3000, for a k8s pod spec
  # ...derived from the exact same declaration, so the two can never drift apart.
}
```

## Options reference

`nixid.lldap.*` (`modules/lldap.nix`):

- `enable`, `package` (a pinning caveat re: SQLite schema versioning lives
  on this option's own description).
- `domain` — convenience default source for `baseDn`/`adminEmail`; leave
  unset and set those two explicitly if your deployment doesn't mirror a
  single domain.
- `baseDn`, `adminUser` (default `"admin"`), `adminEmail`.
- `ldapHost`/`ldapPort` (default `127.0.0.1:389`), `httpHost`/`httpPort`
  (default `127.0.0.1:17170`) — both loopback by default; front with your
  own reverse proxy/tunnel for anything wider.
- `exposeOnInterfaces` — firewall-side interface allowlist for `ldapPort`,
  checked (advisory, never fatal) against live interfaces at boot.
- `jwtSecretFile`, `adminPasswordFile`, `keySeedEnvFile` — no defaults;
  see `keySeedEnvFile`'s own description for why rotating it is
  effectively a full password reset for every user.
- `uid`/`gid` — `null` (auto-allocate) by default; pin to match an
  existing data directory's owner. See the option description for the
  real DynamicUser-vs-tmpfiles-ordering failure this exists to prevent.
- `databaseUrl`, `stateDir`, `stateDirIsBindMount`, `dependsOnUnits`.

`nixid.pocketId.*` (`modules/pocket-id.nix`):

- `enable`, `package`.
- `publicUrl` — no default (see the option description for why a silently
  wrong default here is worse than a required value).
- `trustProxy` (default `true`), `httpHost` (default `127.0.0.1`),
  `httpPort` (default `1411`, mirroring pocket-id's own upstream
  convention).
- `dataDir` (default `/var/lib/pocket-id`) — also the path a real v1→v2
  upgrade self-heal step reads/writes; see the option's own description
  for the exact failure it avoids (a v2 binary silently creating a fresh,
  empty database against a pre-existing v1 layout).
- `encryptionKeyFile` — no default; see "What this deliberately does not
  do" for what this key actually protects.
- `uid`/`gid` — `null` (auto-allocate) by default; pin whenever `dataDir`
  is persisted independently of the host's own NixOS generation history
  (a separate data disk, a restored snapshot). See the option description
  for why this is a different failure than `lldap.nix`'s own `uid` note,
  even though the fix (pin a number) looks the same.

`nixid.posix.*` (`modules/posix.nix`) — see
["Two scopes, one repo"](#two-scopes-one-repo) for why this option group
has no relationship to the two above:

- `enable`.
- `domain` — the identity domain shared by every NFSv4-idmapd-touching
  host in the fleet. Required (non-empty) whenever `enable` is true; see
  the module header for the specific, measured `llistxattr`/`statx`
  slowdown a mismatched value silently causes.
- `identities.<name>` — the registry itself: `uid` (required, no
  default), `gid` (default `null` — a User Private Group equal to `uid`),
  `variant` (`"native"` or `"puid"`, for images that drop privilege
  themselves via `PUID`/`PGID`), `netBind`, `roRootfs`, `reconcile`
  (default `true` — whether an external reconciler is allowed to chown
  this identity's data at all). Every field's own description covers a
  specific, real failure mode it exists to prevent — read them before
  guessing at a value.
- `groups.<name>` — a plain name-to-gid table for groups shared BETWEEN
  identities or hosts, independent of any one identity's own primary
  group.
- `podSecurity.<name>` — read-only, entirely derived from `identities`:
  the Kubernetes `securityContext`, split into `pod`/`container`/`env` to
  match how Kubernetes itself splits one across those three places.
  Consume it from whatever module renders the actual manifest; there is
  no separate place to declare a pod's `runAsUser` by hand, and that
  absence is the whole point.

Two collision assertions fire whenever `enable` is true: no two
identities may share a uid, and no two identities may resolve to the same
gid after UPG resolution — both invisible at declaration time and at
runtime, so both are hard failures rather than warnings.

## Repository layout

```
nixid/
  flake.nix                      # nixosModules.{lldap,pocket-id,posix}
  modules/
    lldap.nix
    pocket-id.nix
    posix.nix
  checks/
    default.nix                  # modules-evaluate + posix-purity
  examples/
    host/                        # all three composed together
    registry-only-host/          # posix.nix alone, nothing else
  experiments/
  studies/
```

## Verifying

Evaluation only — this repo ships no daemon to build, and no VM test yet:

```
nix flake check
# builds two independent check groups:
#   modules-evaluate: all three modules composed into one NixOS system,
#     every assertion evaluated, nothing started
#   posix-purity: nixosModules.posix composed ALONE (examples/registry-only-host)
#     produces the identical systemd.services/environment.systemPackages as the
#     same system without it, and the module's own function never binds `pkgs`
```

That is a real check rather than a smoke test: it forces the full NixOS
evaluation, so a type error, a failed assertion, or a required value nobody
supplied fails it. What it cannot tell you is whether lldap actually serves LDAP
or whether an OIDC login completes — for that, see the live deployment noted
under Status. `posix.nix`'s own guarantee (never running anything, ever) is
different in kind: it is exactly the sort of claim an eval-level check CAN
prove completely, which is what `posix-purity` does, including proving its
own comparisons aren't vacuously true (`checks/default.nix`'s meta-tests).

To just list what the flake exposes:

```
nix eval .#nixosModules --apply "m: builtins.attrNames m"
# => [ "lldap" "pocket-id" "posix" ]
```

## Related projects

`nixid`'s identity-provider stack pairs most directly with
[nixmail](https://github.com/julian-corbet/nixmail-corbet-ch) (a mail
server's LDAP directory *client* config lives there, pointed at the
directory this repo runs) and follows the same design conventions as
[nixnet](https://github.com/julian-corbet/nixnet-corbet-ch) (module
naming, secrets-as-`*File`-options, no hardcoded domain/hostname/IP
anywhere in this repo).

`nixid`'s POSIX registry has a completely different pairing:
[nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch)
resolves every dataset owner and app-leaf identity against
`nixid.posix.identities`/`.groups` (never the other way around — see
["Two scopes, one repo"](#two-scopes-one-repo) for that contract), and
[nixhardware](https://github.com/julian-corbet/nixhardware-corbet-ch)'s
`modules/machines.nix` is the sibling precedent for what a *dedicated*
pure-data registry repo in this family looks like — read there first if
`posix.nix`'s "no systemd, no pkgs, ever" header reads as unfamiliar.

## License

MIT.
