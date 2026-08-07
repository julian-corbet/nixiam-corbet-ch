# nixiam

IAM infrastructure for a self-hosted deployment, packaged as five NixOS
modules under one flake:

Scope note: nixiam covers identity **and access** — including the tooling by which a host
reaches a secret at all (`age`, `sops`) and the vault clients an operator recovers with
(`bitwarden-cli`, `rbw`). Decrypting a secret is an access-control act, so it is filed here
rather than treated as generic developer tooling.

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
3. **A declarative human identity registry** (`users.nix`) — one entry per
   real person: that they exist, which lldap groups they belong to, and
   (by name, into the registry above) which POSIX identity is theirs. Pure
   data, the same discipline as `posix.nix`. See
   ["The human identity registry"](#the-human-identity-registry-and-the-line-that-makes-it-safe)
   below for exactly where this stops and lldap's own runtime state begins.
4. **The mechanism that projects that registry into a running lldap**
   (`lldap-reconcile.nix`) — a systemd timer that creates whatever `users.nix`
   declares and lldap does not have yet, and reports — never silently
   removes — anything lldap has that the registry does not declare. See the
   same section below for why that asymmetry is the single most important
   property of this module.

All five are IAM: identity, access, and credentials for whatever is asking —
a person authenticating through a browser, or a workload asking to open a
file or start a pod as a given uid. That is this repo's whole thesis, and
the reason it is named `nixiam` rather than `nixid`: see
["Why posix folded back in"](#why-posix-folded-back-in) below for the
repository history behind that name, and exactly which option paths moved
as a result.

**Status: alpha.** All five modules are extracted, wired into `flake.nix`,
and checked in CI. Several independent `nix flake check` groups exist —
see [Verifying](#verifying) below.

The lldap and pocket-id modules have also been exercised by an external
consumer. That is runtime evidence, but it is deliberately not an identity
or topology record for this public mechanism repository. The
`modules-evaluate` check establishes that the modules evaluate, not that a
login succeeds. There is still no automated `nixosTest` starting lldap,
binding a port, or performing an OIDC round trip.

## Public mechanism, private registry

This public repository owns the option schema, validation, derived
`podSecurity` shape and reconciliation mechanism. A consumer's actual account
names, people, email addresses, group memberships, UID/GID assignments,
identity domain, endpoints and keys belong in that consumer's private
infrastructure/secrets repository. They are not secrets in the narrow
cryptographic sense, but together they are an account and authorization map.

Examples and checks here use invented names and numbers only. Public nixiam
must never become the canonical numeric/account registry for a real
deployment; it provides the type-safe mechanism that a private registry
instantiates.

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
  module's own header comment for the failure mode behind
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
- **`users.nix`** — the human identity registry: `nixiam.users.<name> =
  { posixIdentity; groups; displayName; email; enable; acknowledgeRemoval;
  }`. Pure data, the identical discipline as `posix.nix` — no `pkgs`
  argument, no `systemd.services`, nothing that ever runs. Declares that a
  human exists, which lldap groups they belong to, and (by NAME into
  `nixiam.posix.identities`, never a raw uid) which POSIX identity is
  theirs. See ["The human identity registry"](#the-human-identity-registry-and-the-line-that-makes-it-safe)
  below for exactly where this registry stops and lldap's own runtime
  state begins.
- **`lldap-reconcile.nix`** — the mechanism, and the only thing in this
  repo allowed to read `nixiam.users` and act on it: a systemd timer that
  creates whatever a declared, `enable = true` person is missing from a
  running lldap directory (their account, any group they should belong to,
  that membership), and REPORTS — never silently removes — anything lldap
  has that the registry does not declare. The one, deliberately narrow,
  opt-in exception is covered in the same section below.
- **`vaultwarden.nix`** — a self-hosted, Bitwarden-compatible password
  vault, with pocket-id wireable in as an OPTIONAL OIDC/SSO front door
  (`nixiam.vaultwarden.sso.*`) alongside — never instead of — the master
  password. Manages the vaultwarden PROCESS only (listener, database
  backend, a pinned uid/gid), the same non-goal `lldap.nix` states for
  itself: what's actually stored in the vault is live state this module
  never touches. See the module's own header for why the master password
  stays even with SSO on.

lldap, pocket-id and vaultwarden are named after the real upstream project
behind them, not an abstract role ("ldap-directory", "oidc-provider",
"password-vault") — a generic interface with exactly one implementation
behind it documents a boundary that doesn't exist. If a second directory,
SSO, or vault backend is ever added here, it gets its own module.
`posix.nix` and `users.nix` have no upstream project behind them at all —
both are this repo's own pure-data tables, named for what they hold rather
than what they wrap.

## The human identity registry, and the line that makes it safe

A human identity today has (at least) four independent places that each
claim to know who they are: a POSIX uid/gid, an lldap directory entry, a
network ACL group, and a local Unix account. None of the four asserts that
it agrees with any of the others — exactly the duplication this repo
already removed once for a disk
([nixstorage](https://github.com/julian-corbet/nixstorage-corbet-ch)'s
`disks`) and once for an app/container identity (`posix.identities` above).
`users.nix` is the same fix applied to a HUMAN, with one line drawn
deliberately, because the failure mode on the wrong side of it is worse
than a drifted uid: lldap sits behind the SSO shared across hosts, so getting the
CREDENTIAL half of this wrong does not just corrupt a file, it locks a
real person out of everything at once, or leaks the one secret that
unlocks every directory entry simultaneously.

**NON-SECRET DEPLOYMENT CONFIGURATION** — declared in
`nixiam.users.<name>`, but kept in the consuming deployment's private Infra
because it maps real people and authorization:

- that this name exists as a human identity at all
- which lldap groups they belong to (additive membership only — see below)
- which `nixiam.posix.identities.<name>` entry is their uid/gid, by NAME,
  never a raw number restated here
- a display name and a contact email

**STATE** — never here, never movable here no matter how it's stored:

- password hashes, TOTP secrets, sessions, last-login. lldap owns these
  exclusively, permanently — not a policy choice, a structural property of
  the Nix store being world-readable on every machine that has ever built
  this configuration. `lldap-reconcile.nix`'s own generated script cannot
  even accidentally cross this line: lldap's `CreateUserInput`/
  `UpdateUserInput` GraphQL types have no password field of any kind (see
  `lldap-reconcile.nix`'s own header for exactly where that was confirmed).
- anything a human changes about their own account at runtime — a password
  reset must never require a redeploy, the same reason `lldap.nix`'s own
  `adminPasswordFile` is read once, at first start, and never re-applied.

### The reconciler never deletes — the load-bearing decision

`lldap-reconcile.nix` creates a declared user if absent, creates a declared
group if absent, and creates a declared membership if absent. It does
**not** remove a user or a membership lldap has that the registry does not
declare — not once, not ever, by default — because lldap sitting behind
SSO means a deletion locks a real person out of every service behind it
simultaneously, with no automatic undo once the mutation lands. Undeclared
drift is reported: a `WARN` line naming exactly what is undeclared, and a
non-zero exit, every single reconcile tick until the drift is resolved one
way or the other by a human.

This mirrors a decision this same nix* family already made for the
identical reason: [nixiac](https://github.com/julian-corbet/nixiac-corbet-ch)
inverts Crossplane's own default management policy from
"observe, create, update, delete" to "observe only, orphan on removal",
specifically because a destructive default must be asked for in writing
rather than inherited from a framework.

The ONE way to get an actual deletion out of this reconciler is per-person
and opt-in: set `nixiam.users.<name>.enable = false` and
`nixiam.users.<name>.acknowledgeRemoval` to a written reason (a sentence,
not a boolean — the identical `nixiac`-style reasoning: a boolean is
invisible in a diff and in `git blame`; a sentence survives both). Leaving
`acknowledgeRemoval` unset with `enable = false` reports that person as
drift and leaves them alone forever, same as a name the registry has never
heard of at all.

Both properties — idempotency (running twice performs zero mutations the
second time) and the deletion-refusal behavior in both directions — were
proven by actually executing this repo's own generated script against a
local mock of lldap's API, never a live lldap; see
[`experiments/README.md` #012](experiments/README.md#012--lldap-reconcile-idempotency--deletion-refusal-executed-against-a-local-mock)
and its write-up in `studies/README.md`.

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
| `config.nixid.posix.groups.<name>` | `config.nixposix.groups.<name>` | `config.nixiam.posix.groups.<name>.gid` |
| `config.nixid.posix.podSecurity.<name>` | `config.nixposix.podSecurity.<name>` | `config.nixiam.posix.podSecurity.<name>` |

The current group shape is intentionally a clean break from the earlier
integer leaf: write `groups.<name> = { gid = 3100; };`, not
`groups.<name> = 3100;`. The structured entry is what makes a
reason-bearing `encountered` exception possible without adding a second
group table or weakening the private-band assertion globally.

Known public mechanism consumers at the time of this fold-back, checked by
direct source read: `nixstorage`'s `modules/reconciler.nix`, `nixmail`'s
`modules/stalwart.nix`, and `nixarch`'s `modules/device-gids.nix` all read
`config.nixiam.posix.*` today and needed this path change (from whichever
of the two older paths they were on). `nixluks` was also checked and does
**not** actually read it — its own `modules/nixluks.nix` only cites the
registry's defensive-read pattern as prior art in a comment, while reading
`config.nixstorage.disks` itself; it needs no change.

⚠ **THIS IS A HARD CUTOVER, AND IT FAILS SILENTLY.** All three known
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
- **No secrets, credentials, or passwords of any kind.** The schema is
  public, but a real registry's numbers, names and policy stay in private
  Infra. If a future identity
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

The failure this one shared value exists to prevent is difficult to
diagnose because BASIC ownership keeps working the entire time it is
broken. NFSv4 maps uids/gids to and from
`name@domain` strings on the wire; if a client's idmapd `Domain=` does not
match the server's, idmapd silently falls back to guessing the domain
from the client's own DNS search domain instead — and if that guess
doesn't match either, every NFSv4 ACL-touching syscall starts paying a
failed kernel upcall: `llistxattr` (reading the NFSv4 ACL attribute),
`getfacl`, and the per-entry `stat`/`statx` a file manager or shell issues
while just listing a directory. A failed upcall can make ACL-related
metadata operations extremely slow even for a plain directory. Ordinary
AUTH_SYS ownership checks (owner/group/
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

  # Synthetic shape example only. A real POSIX registry belongs in the
  # consumer's private infrastructure repository.
  nixiam.posix = {
    enable = true;
    domain = "example.org";       # shared NFSv4-idmapd domain; see the module's own header
    identities.exampleService.uid = 3000;  # invented fixture value
  };

  # config.nixiam.posix.identities.exampleService.uid -> 3000
  # config.nixiam.posix.podSecurity.exampleService.pod.runAsUser -> 3000
  # ...derived from the exact same declaration, so the two can never drift apart.

  # The human identity registry -- independent of everything above; declares real people and
  # projects them into the lldap directory running above.
  nixiam.users.jane = {
    posixIdentity = null;              # SSO-only: no shell, no POSIX uid at all
    groups = [ "admins" ];
    displayName = "Jane Doe";
    email = "jane@example.org";
  };

  # The mechanism that actually reads nixiam.users and converges lldap to it -- a systemd timer,
  # independent of nixiam.lldap running on THIS host (it can point at a remote one via apiUrl).
  nixiam.lldapReconcile = {
    enable = true;
    credentialFile = "/run/secrets/lldap-reconcile-admin"; # NEVER a Nix store path -- asserted
  };
}
```

A host that wants ONLY the POSIX uid/gid registry — no LDAP directory, no
OIDC/SSO provider, nothing that runs — imports `nixiam.nixosModules.posix`
alone; see [`examples/posix-registry/configuration.nix`](examples/posix-registry/configuration.nix)
for the full worked version `checks/default.nix`'s `posix-purity` group
runs against. `examples/users-registry/configuration.nix` is the
equivalent worked example for `users.nix` + `posix.nix` together — a human
WITH a POSIX identity, one WITHOUT, and one declared but disabled without
being deleted from the file.

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
- `groups.<name>` — groups shared BETWEEN identities or hosts,
  independent of any one identity's own primary group. Each entry has a
  required `gid` and optional reason-bearing `encountered` string. The
  latter is for externally fixed groups such as a distro's `users(100)`;
  without it the gid must remain inside `identityRange`.
- `podSecurity.<name>` — read-only, entirely derived from `identities`:
  the Kubernetes `securityContext`, split into `pod`/`container`/`env` to
  match how Kubernetes itself splits one across those three places.
  Consume it from whatever module renders the actual manifest; there is
  no separate place to declare a pod's `runAsUser` by hand, and that
  absence is the whole point.

Collision assertions fire whenever `nixiam.posix.enable` is true: no two
identities may share a uid, and no two declarations across identities,
shared groups, and device groups may claim the same resolved gid. An
`encountered` exception changes range policy only; it never bypasses
collision detection.

`nixiam.users.*` (`modules/users.nix`):

- `<name>.enable` (default `true`) — whether the reconciler may create this
  person and converge their memberships; `false` reports them as drift
  instead of removing them, unless paired with `acknowledgeRemoval`.
- `<name>.posixIdentity` — name into `nixiam.posix.identities`, or `null`
  (default) for a pure SSO-only human with no POSIX/local-account
  correspondence. Asserted to resolve whenever set AND `nixiam.posix` is
  actually imported; silent otherwise, so this module is adoptable before
  `posix.nix` is wired up on a given host.
- `<name>.groups` (default `[ ]`) — lldap group membership by display
  name, additive only.
- `<name>.displayName`, `<name>.email` — no defaults; see each option's own
  description for why inventing one would be worse than requiring it.
- `<name>.acknowledgeRemoval` — a written reason (no default), the ONE
  opt-in path to an actual deletion, only effective when `enable = false`.
  Asserted against being set together with `enable = true` (a
  contradiction: create-and-keep vs. delete cannot both be the intent).

`nixiam.lldapReconcile.*` (`modules/lldap-reconcile.nix`):

- `enable`, `apiUrl` (default `http://127.0.0.1:17170`, matching
  `nixiam.lldap`'s own defaults for co-located use), `adminUsername`
  (default `"admin"`).
- `credentialFile` — no default; asserted to never resolve inside the Nix
  store. Re-read fresh every reconcile run to mint a short-lived bearer
  token — there is no long-lived API key to cache instead.
- `dependsOnUnits`, `onBootSec` (default `5min`), `interval` (default
  `30min`).

## Repository layout

```
nixiam/
  flake.nix                            # nixosModules.{lldap,pocket-id,vaultwarden,posix,users,lldap-reconcile}; systemManagerModules/darwinModules.posix
  modules/
    lldap.nix
    pocket-id.nix
    vaultwarden.nix                    # password vault; optional pocket-id SSO front door
    posix.nix
    users.nix                          # the human identity registry -- pure data
    lldap-reconcile.nix                # the mechanism: reads users.nix, converges a running lldap
  checks/
    default.nix                        # modules-evaluate (all six composed); eval-tests (posix-purity, module, podSecurity, backend-parity, example, users-registry, lldap-reconcile)
  examples/
    host/                              # lldap + pocket-id composed together
    posix-registry/                    # posix alone -- the registry-only fixture the purity/backend-parity checks run against
    users-registry/                    # users + posix together -- the posixIdentity cross-reference worked example
  experiments/
    mock-lldap.py                      # local stand-in for lldap's HTTP API -- never a live lldap
    lldap-reconcile-harness.nix        # builds the real nixiam-lldap-reconcile script against it
    run-lldap-reconcile-proof.sh       # idempotency + deletion-refusal, actually executed
  studies/
```

## Verifying

Evaluation only — this repo ships no daemon to build, and no VM test yet:

```
nix flake check
# builds several check groups:
#   modules-evaluate: lldap, pocket-id, posix, users, and lldap-reconcile
#     composed into one NixOS system (examples/host -- posix/users/
#     lldap-reconcile all ride along disabled or empty), every assertion
#     evaluated, nothing started
#   eval-tests: modules/posix.nix's own five groups (posix-purity, module,
#     podSecurity, backend-parity, example) against examples/posix-registry,
#     plus users-registry (modules/users.nix's posixIdentity assertion, in
#     both directions, PLUS the silent-when-nixiam.posix-is-not-imported
#     case) and lldap-reconcile (the credentialFile-outside-the-store
#     assertion, in both directions)
```

None of the above starts lldap-reconcile's own systemd unit or runs its
script against anything -- that is a runtime property of a shell script
talking to an HTTP API, not something Nix evaluation can demonstrate on its
own. That proof exists, and was actually executed, against a local mock of
lldap's API (never a live lldap) in `experiments/` -- see
["The human identity registry"](#the-human-identity-registry-and-the-line-that-makes-it-safe)
above, `experiments/README.md` #012, and its write-up in `studies/README.md`.

That is a real check rather than a smoke test: it forces the full NixOS
evaluation, so a type error, a failed assertion, or a required value nobody
supplied fails it. What it cannot tell you is whether lldap actually serves LDAP
or whether an OIDC login completes — for that, see the live deployment noted
under Status.

To just list what the flake exposes:

```
nix eval .#nixosModules --apply "m: builtins.attrNames m"
# => [ "lldap" "lldap-reconcile" "pocket-id" "posix" "users" ]
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
`posix.nix`'s own `flake.nix` shape (the same file exported as
`nixosModules`/`systemManagerModules`/`darwinModules`) and testing discipline
(`posix-purity`-style mechanical enforcement, backend-parity checks) follow
the same pattern [nixhost](https://github.com/julian-corbet/nixhost-corbet-ch),
the sibling pure-data namespace root, uses for the identical three-backend
shape.

## License

MIT.
