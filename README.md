# nixiam

IAM infrastructure for a self-hosted deployment, packaged as three NixOS
modules under one flake:

1. **An identity-provider stack** — an LDAP directory
   ([lldap](https://github.com/lldap/lldap)) and the OIDC/SSO provider
   ([pocket-id](https://github.com/pocket-id/pocket-id)) that sits in front
   of it. This is "identity" in the everyday sense — a human's login and
   the directory that remembers it.
2. **A cross-host POSIX uid/gid registry** (`posix.nix`) — one uid/gid per
   name, and the Kubernetes `securityContext` each identity implies,
   generated from the same declaration. Pure data — no daemon, no process,
   nothing that ever starts. This is "identity" in a completely different
   sense — which number a host or container runs as, and what it is
   allowed to touch — not a human's login credential at all.

Both are IAM: identity, access, and credentials for whatever is asking —
a person authenticating through a browser, or a workload asking to open a
file or start a pod as a given uid. That is this repo's whole thesis, and
the reason it is named `nixiam` rather than `nixid`: see
["Why posix folded back in"](#why-posix-folded-back-in) below for the
repository history behind that name, and exactly which option paths moved
as a result.

**Status: alpha.** All three modules are extracted, wired into `flake.nix`,
and checked in CI. Two independent `nix flake check` groups exist for two
independent reasons — see [Verifying](#verifying) below.

lldap and pocket-id are also running live in a real production deployment
(a small single-node host, outside this repo), and the identity chain
behind that deployment's mail stack has been verified end to end. That
remains the stronger evidence for those two modules — the `modules-evaluate`
check establishes that they evaluate, not that a login succeeds. There is
still no automated `nixosTest` starting lldap, binding a port, or
performing an OIDC round trip.

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
options, or whatever else you point at this directory. Nor does it walk a
dataset tree and call `chown` — `posix.nix` answers only "who" (a uid/gid
and the securityContext it implies); a sibling repo,
[nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch),
answers "where, and what shape" and is the one thing allowed to consume
this registry, never the other way around.

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
- **`posix.nix`** — the cross-host POSIX identity registry:
  `nixiam.posix.identities.<name> = { uid; gid; variant; ... }` and,
  generated straight from it, `nixiam.posix.podSecurity.<name>` — the
  Kubernetes `securityContext` that identity implies, split into
  `pod`/`container`/`env` the same way Kubernetes itself splits a
  securityContext across those three places. Nothing else across hosts
  should ever declare a raw uid/gid number a second time next to a
  dataset path or a pod spec; it declares a NAME here instead. THIS
  MODULE IS PURE DATA — no `systemd.services`, no
  `environment.systemPackages`, no `pkgs` argument at all, not even a
  `users.users`/`users.groups` entry. See "Why posix folded back in"
  below for the full reasoning behind that boundary, and
  `checks/default.nix`'s `posix-purity` group for where it is
  mechanically enforced, not merely argued.

lldap and pocket-id are named after the real upstream project behind them,
not an abstract role ("ldap-directory", "oidc-provider") — a generic
interface with exactly one implementation behind it documents a boundary
that doesn't exist. If a second directory or SSO backend is ever added
here, it gets its own module. `posix.nix` has no upstream project behind
it at all — it is this repo's own pure-data table, named for what it holds
rather than what it wraps.

## Why posix folded back in

`posix.nix` was a cross-host table of "this name is uid N, gid M" and the
Kubernetes `securityContext` it implies — pure data, no daemon, no
process, nothing that ever ran. It shared this repo (then named `nixid`)
with the two real, running services above, until a genuine split moved it
out to its own repository, `nixposix`, on two grounds: a uid/gid table is
portable to every backend an operator manages (NixOS, system-manager, AND
nix-darwin — nixid's own `lldap`/`pocket-id` have no nix-darwin
equivalent, so nixid never exported `darwinModules` at all), and the
registry has no relationship to LDAP or OIDC whatsoever — a reader
arriving at a repo named for an identity-provider stack to find a
completely unrelated POSIX uid/gid table was a real discoverability cost.

That split is now reversed, and `posix.nix` is back — as `nixiam.posix.*`,
under an ADDED `.posix` level it never had as a bare `nixposix.*`, and
under a repo renamed from `nixid` to `nixiam` to say plainly what it
actually is: **identity, access, and credentials for a host or
container**, not merely "id". ACL, POSIX uid/gid, and cross-host gid
convergence are all facets of the same question `lldap`/`pocket-id`
already answer for a human — WHO this is and WHAT it may do — so they
belong in the same repo, under the acronym the industry already uses for
exactly this question, rather than in three repos split by upstream-project
boundary instead of by what the question actually is. The discoverability
cost the original split was reasoned against is smaller than the cost of
scattering one coherent question — identity and access — across
repositories that each only answer one slice of it.

What did NOT change: `posix.nix` is exactly the file it was as `nixposix`
(down to its own option descriptions), it still exports to
`nixosModules`, `systemManagerModules`, **and** `darwinModules` from the
same file (a uid/gid table has no reason not to), and it still ports to
every backend `lldap.nix`/`pocket-id.nix` cannot (see "What this
deliberately does not do" below for the specific system-manager barrier
those two have never been assessed against). Only the repo it lives in,
and the option prefix in front of it, moved.

**If anything across hosts still imports `nixposix.nixosModules.posix` (or,
further back, `nixid.nixosModules.posix`), it no longer exists.** Every
option path changes as follows:

| Oldest (inside nixid, pre-split) | Middle (standalone nixposix) | Current (nixiam) |
|---|---|---|
| `config.nixid.posix.enable` | `config.nixposix.enable` | `config.nixiam.posix.enable` |
| `config.nixid.posix.domain` | `config.nixposix.domain` | `config.nixiam.posix.domain` |
| `config.nixid.posix.identities.<name>` | `config.nixposix.identities.<name>` | `config.nixiam.posix.identities.<name>` |
| `config.nixid.posix.groups.<name>` | `config.nixposix.groups.<name>` | `config.nixiam.posix.groups.<name>` |
| `config.nixid.posix.podSecurity.<name>` | `config.nixposix.podSecurity.<name>` | `config.nixiam.posix.podSecurity.<name>` |

Known real consumers at the time of this fold-back, checked by direct
source read: `nixstorage`'s `modules/reconciler.nix`, `nixmail`'s
`modules/stalwart.nix`, and `nixarch`'s `modules/device-gids.nix` all read
`config.nixiam.posix.*` today and needed this path change (from whichever
of the two older paths they were on). `nixluks` was also checked and does
**not** actually read it — its own `modules/nixluks.nix` only cites the
registry's defensive-read pattern as prior art in a comment, while reading
`config.nixstorage.disks` itself; it needs no change.

⚠ **THIS IS A HARD CUTOVER, AND IT FAILS SILENTLY.** All three real
consumers read the option defensively (`config.nixiam.posix.… or { }`),
which is exactly why the fix in each case is a one-line path change, never
a new flake input — none of nixstorage, nixmail, or nixarch take `nixiam`
(or, at either earlier point, `nixid`/`nixposix`) as a flake input at all.
That same defensiveness also means a consumer still reading the OLD path
does **not** get an evaluation error: identities and groups simply
**vanish** — no assertion, no warning, and a reconciler that was chowning
trees to declared uids quietly finds nothing to do. That is the same class
of failure as a glob matching nothing: the safety mechanism absorbs the
error. So the three consumer repos above must be repointed **in lockstep
with, or before**, any host that adopts the renamed `nixiam` — never on a
lazy migration schedule.

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

Also out of scope:

- **A real NixOS VM test** (`nixosTest`) exercising `lldap.nix`/
  `pocket-id.nix` against actual service startup, beyond pure evaluation.
  Not started.
- **`systemManagerModules.lldap`/`."pocket-id"`** — not evaluated for
  this repo. `pocket-id.nix` in particular touches `users.users`/
  credentials primitives that may or may not map cleanly onto
  `system-manager`'s smaller surface. Unassessed, not attempted. `posix.nix`
  has no such barrier — pure data, no `pkgs` argument at all — which is
  exactly why it, alone of the three, exports `systemManagerModules` and
  `darwinModules`.
- **`darwinModules.posix` proven against a real nix-darwin evaluation.**
  The alias is offered on the strength of the same "bare `options`/
  `config.assertions`" reasoning that makes `systemManagerModules.posix`
  work, but no `nix-darwin` input exists in this repo's own CI to prove it
  — see `experiments/README.md` #008.
- **The `groups`/`reconcile` half of `posix.nix` exercised against a real
  reconciler.** `checks/` proves the registry's shape (readable, typed,
  collision-free); it does not prove that `nixstorage`'s reconciler
  behaves correctly against it — see `experiments/README.md` #009.

## The safety model: `posix.nix` never runs anything

Stated once, here, because it is the invariant every check in this
module's test group exists to uphold, and the property that makes it safe
for even the smallest host to import:

- **No `systemd.services`, no `environment.systemPackages`, no `pkgs`
  argument at all.** Not even a `users.users`/`users.groups` entry —
  nothing this module declares ever runs, writes a file, or touches
  `/etc/passwd`. A ZFS chown target and a Kubernetes `runAsUser` both take
  a bare number; neither needs a resolvable `/etc/passwd` line on THIS
  host to mean anything.
- **No secrets, credentials, or passwords of any kind.** This registry is
  entirely public-shape numbers and booleans; if a future identity
  genuinely needs a secret, that belongs in whatever module actually runs
  that app — the same way this repo's own `lldap.nix` keeps its
  `jwtSecretFile` on itself rather than on the registry.
- **Never a mechanism, only a table.** If a future need genuinely wants
  automation over this data (walking `identities` and calling `chown`,
  say), that automation belongs in the module that already knows about
  paths and datasets — never here. The moment this module grows a systemd
  unit "just this once," every future host that imports it for the data
  alone also inherits whatever that unit does, whether or not it has the
  storage the unit assumes. Concretely: this registry answers "who"; a
  sibling module elsewhere (`nixstorage`) answers "where, and what shape,"
  and is the one thing allowed to consume this one, never the other way
  around.

This is no longer just an argument in prose. `checks/default.nix`'s
`posix-purity` group fails `nix flake check` if `posix.nix`'s own function
ever binds a `pkgs` argument, or if composing `nixosModules.posix` alone
(see `examples/posix-registry`) ever changes `systemd.services` or
`environment.systemPackages` relative to the identical system with the
module absent entirely — with meta-tests proving the comparison itself
has teeth, not merely that the real module happens not to violate it
today.

## The `domain` failure `posix.nix` exists to prevent

`nixiam.posix.domain` is the identity domain every host shares for
anything that maps NAMES across a trust boundary rather than trusting
numbers directly. Its first, and so far only, real consumer is NFSv4
idmapd's own `Domain=` setting.

The failure this one shared value exists to prevent is not hypothetical,
and it is genuinely nasty to diagnose, because BASIC ownership keeps
working the entire time it is broken. NFSv4 maps uids/gids to and from
`name@domain` strings on the wire; if a client's idmapd `Domain=` does not
match the server's, idmapd silently falls back to guessing the domain
from the client's own DNS search domain instead — and if that guess
doesn't match either, every NFSv4 ACL-touching syscall starts paying a
failed kernel upcall: `llistxattr` (reading the NFSv4 ACL attribute),
`getfacl`, and the per-entry `stat`/`statx` a file manager or shell issues
while just listing a directory. Measured cold, on a real host, against a
single plain directory:

```
llistxattr   7.5 s
statx        1.6 s
```

...for ONE directory. Ordinary AUTH_SYS ownership checks (owner/group/
other bits, the numeric uid/gid a `stat()` returns) are completely
unaffected, because AUTH_SYS passes uids and gids over the wire as plain
NUMBERS — no name mapping, no idmapd involvement at all. That is exactly
why this goes unnoticed for so long in practice: files still open, still
read, still show the right owner; only the NFSv4-ACL-specific path is
silently paying seconds per call, and nothing in the symptom points at
"domain string mismatch" as the cause. One value, declared once here and
referenced by every idmapd-touching module on every host that shares this
registry's users, is what makes it structurally impossible for the two
ends to drift apart by a typo.

`nixiam.posix.groups` guards the same class of failure from the other
protocol path: NFS's AUTH_SYS security flavor authenticates a request by
sending the calling uid/gid as plain numbers, with no name lookup at all.
If the SAME group name resolves to DIFFERENT gid numbers on two machines
that share an NFS export, each machine's kernel still faithfully checks
"does the caller's numeric gid match the file's numeric gid" — and gets a
different answer depending on which machine asked, silently granting
access on one and denying it on the other. This has been observed across a
real, small multi-machine deployment: a group left to auto-allocate
independently on each host ended up numbered differently on each one, and
reconverging it required an explicit rename pass on every machine that had
drifted, after the mismatch was already causing wrong access. Declaring
the number once, here, is what makes that drift structurally impossible
instead of something to remember to check.

## Quickstart

```nix
{
  inputs.nixiam.url = "github:<owner>/<repo>"; # no public remote yet

  # host configuration.nix:
  imports = [
    inputs.nixiam.nixosModules.lldap
    inputs.nixiam.nixosModules."pocket-id"
    inputs.nixiam.nixosModules.posix
  ];

  nixiam.lldap = {
    enable = true;
    domain = "example.org";                       # placeholder — your real domain
    jwtSecretFile = "/run/secrets/lldap-jwt";
    adminPasswordFile = "/run/secrets/lldap-admin";
    keySeedEnvFile = "/run/secrets/lldap-seed";
  };

  nixiam.pocketId = {
    enable = true;
    publicUrl = "https://id.example.org";
    encryptionKeyFile = "/run/secrets/pocket-id-encryption-key";
  };

  # Then, once, through the running pocket-id instance's own admin UI:
  # point its LDAP sync at ldap://127.0.0.1:389 / the baseDn above, with a
  # bind DN and password of your choosing. Not a step this flake can do
  # for you — see "What this deliberately does not do".

  # The cross-host POSIX registry -- independent of the two services
  # above; a host may declare this and neither of them, or vice versa.
  nixiam.posix = {
    enable = true;
    domain = "example.org";       # shared NFSv4-idmapd domain; see the module's own header
    identities.myapp.uid = 3000;  # gid defaults to a User Private Group
  };

  # config.nixiam.posix.identities.myapp.uid           -> 3000, for a ZFS chown
  # config.nixiam.posix.podSecurity.myapp.pod.runAsUser -> 3000, for a k8s pod spec
  # ...derived from the exact same declaration, so the two can never drift apart.
}
```

A host that wants ONLY the POSIX uid/gid registry — no LDAP directory, no
OIDC/SSO provider, nothing that runs — imports `nixiam.nixosModules.posix`
alone; see [`examples/posix-registry/configuration.nix`](examples/posix-registry/configuration.nix)
for the full worked version `checks/default.nix`'s `posix-purity` group
runs against.

## Two backends proven, one offered as-is (for `posix.nix`)

`nixosModules.posix`, `systemManagerModules.posix`, and
`darwinModules.posix` all point at the exact same file, unchanged —
possible because the module only ever touches `options`/`config.assertions`,
primitives every module system built on `lib.evalModules` shares, and
never `pkgs`, `systemd`, or any NixOS-only integration. `checks/default.nix`'s
`backend-parity` group proves this for NixOS and system-manager: the same
fixtures (a valid registry, a missing domain, a uid collision, a gid
collision) evaluated through both `nixpkgs/nixos/lib/eval-config.nix` and
system-manager's own `makeSystemConfig`, asserting each one fails — or
builds — identically on both. The `darwinModules` alias is offered on the
strength of the same reasoning but is **not yet backed by a check** — no
`nix-darwin` input exists in this repo's own CI. See
`experiments/README.md` #008.

`lldap.nix`/`pocket-id.nix` have NO such parity claim — see "What this
deliberately does not do" above.

## Options reference

`nixiam.lldap.*` (`modules/lldap.nix`):

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

`nixiam.pocketId.*` (`modules/pocket-id.nix`):

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

`nixiam.posix.*` (`modules/posix.nix`):

- `enable`.
- `domain` — the identity domain shared by every NFSv4-idmapd-touching
  host in this registry. Required (non-empty) whenever `enable` is true; see
  ["The `domain` failure"](#the-domain-failure-posixnix-exists-to-prevent)
  above for the specific, measured `llistxattr`/`statx` slowdown a
  mismatched value silently causes.
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

Two collision assertions fire whenever `nixiam.posix.enable` is true: no
two identities may share a uid, and no two identities may resolve to the
same gid after UPG resolution — both invisible at declaration time and at
runtime, so both are hard failures rather than warnings.

## Repository layout

```
nixiam/
  flake.nix                            # nixosModules.{lldap,pocket-id,posix}; systemManagerModules/darwinModules.posix
  modules/
    lldap.nix
    pocket-id.nix
    posix.nix
  checks/
    default.nix                        # modules-evaluate (lldap+pocket-id+posix); eval-tests (posix-purity, module, podSecurity, backend-parity, example)
  examples/
    host/                              # lldap + pocket-id composed together
    posix-registry/                    # posix alone -- the registry-only fixture the purity/backend-parity checks run against
  experiments/
  studies/
```

## Verifying

Evaluation only — this repo ships no daemon to build, and no VM test yet:

```
nix flake check
# builds two check groups:
#   modules-evaluate: lldap, pocket-id, and posix composed into one NixOS
#     system (examples/host — posix rides along disabled), every
#     assertion evaluated, nothing started
#   eval-tests: modules/posix.nix's own five groups (posix-purity, module,
#     podSecurity, backend-parity, example), against examples/posix-registry
```

That is a real check rather than a smoke test: it forces the full NixOS
evaluation, so a type error, a failed assertion, or a required value nobody
supplied fails it. What it cannot tell you is whether lldap actually serves LDAP
or whether an OIDC login completes — for that, see the live deployment noted
under Status.

To just list what the flake exposes:

```
nix eval .#nixosModules --apply "m: builtins.attrNames m"
# => [ "lldap" "pocket-id" "posix" ]
```

## Related projects

Pairs most directly with
[nixmail](https://github.com/julian-corbet/nixmail-corbet-ch) (a mail
server's LDAP directory *client* config lives there, pointed at the
directory this repo runs) and follows the same design conventions as
[nixnet](https://github.com/julian-corbet/nixnet-corbet-ch) (module
naming, secrets-as-`*File`-options, no hardcoded domain/hostname/IP
anywhere in this repo).

[nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch),
[nixmail](https://github.com/julian-corbet/nixmail-corbet-ch), and
[nixarch](https://github.com/julian-corbet/nixarch-corbet-ch) all read
`nixiam.posix.*` (see ["Why posix folded back in"](#why-posix-folded-back-in)
above for the exact paths) — never the reverse; this repo must never learn
a dataset path, a mail user, or a device name.
[nixmachines](https://github.com/julian-corbet/nixmachines-corbet-ch) is
the sibling pure-data registry `posix.nix`'s own `flake.nix` shape (the
same file exported as `nixosModules`/`systemManagerModules`/`darwinModules`)
and testing discipline (`posix-purity`-style mechanical enforcement,
backend-parity checks) were both copied from.

## License

MIT.
