# nixid

Identity infrastructure for a self-hosted stack: an LDAP directory
([lldap](https://github.com/lldap/lldap)) and the OIDC/SSO provider
([pocket-id](https://github.com/pocket-id/pocket-id)) that sits in front
of it, packaged as two independent NixOS modules.

**Status: alpha.** Both modules are extracted, wired into `flake.nix`, and
checked in CI: `nix flake check` composes them into one NixOS system from
[examples/host](examples/host), which exercises every assertion either module
makes and — because both live under `nixid.*` — is the only thing that
can catch a collision between them. Proven in the failing direction too:
removing a required credential path or mistyping a value fails the check by name.

Both are also running live in a real production deployment (a small single-node
host, outside this repo), and the identity chain behind that deployment's mail
stack has been verified end to end. That remains the stronger evidence — the
check establishes that the modules evaluate, not that a login succeeds. There is
still no automated `nixosTest` starting lldap, binding a port, or performing an
OIDC round trip.

## Scope

Identity is its own concern, not a feature of any one consumer. This repo
exists specifically because a mail stack is only ONE of several things
that authenticate against an identity directory — a self-hosted git forge
and a Kubernetes dashboard are two more, equally valid, equally unrelated
to mail. Bundling `lldap`/`pocket-id` inside a mail-transport repo would
have made every non-mail consumer depend on a package whose name and
scope had nothing to do with what they actually needed. See
[nixmail](https://github.com/julian-corbet/nixmail-corbet-ch)'s own
README for the mirror image of this decision: it deliberately ships no
directory server or SSO provider and says so, pointing here instead.

This repo, in turn, ships no mail transport, no webmail, and no
mail-specific LDAP schema (which groups/attributes a mail server expects
to find in the directory) — that's `nixmail`'s `stalwart.nix` `ldap.*`
options, or whatever else you point at this directory. `nixid` only ever
runs the directory server and the identity provider in front of it.

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

Both modules are named after the real upstream project behind them, not
an abstract role ("ldap-directory", "oidc-provider") — a generic
interface with exactly one implementation behind it documents a boundary
that doesn't exist. If a second directory or SSO backend is ever added
here, it gets its own module, same as `nixmail`'s sibling services.

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
attribute names a consumer expects to find): that genuinely is
Nix-declarable and belongs in whichever module consumes the directory —
a materially different kind of "not shipped here" than pocket-id's.

Also out of scope, same reasoning as `nixmail`'s own equivalent section:

- **A real NixOS VM test** (`nixosTest`) exercising both modules against
  actual service startup, beyond pure evaluation. Not started.
- **`systemManagerModules`** — not evaluated for this repo. `pocket-id.nix`
  in particular touches `users.users`/credentials primitives that may or
  may not map cleanly onto `system-manager`'s smaller surface. Unassessed,
  not attempted.

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

## Repository layout

```
nixid/
  flake.nix                    # nixosModules.{lldap,pocket-id}
  modules/
    lldap.nix
    pocket-id.nix
```

## Verifying

Evaluation only — this repo ships no daemon to build, and no VM test yet:

```
nix flake check
# builds checks.<system>.modules-evaluate: both modules composed into one
# NixOS system, every assertion evaluated, nothing started
```

That is a real check rather than a smoke test: it forces the full NixOS
evaluation, so a type error, a failed assertion, or a required value nobody
supplied fails it. What it cannot tell you is whether lldap actually serves LDAP
or whether an OIDC login completes — for that, see the live deployment noted
under Status.

To just list what the flake exposes:

```
nix eval .#nixosModules --apply "m: builtins.attrNames m"
# => [ "lldap" "pocket-id" ]
```

## Related projects

`nixid` pairs most directly with
[nixmail](https://github.com/julian-corbet/nixmail-corbet-ch) (a mail
server's LDAP directory *client* config lives there, pointed at the
directory this repo runs) and follows the same design conventions as
[nixnet](https://github.com/julian-corbet/nixnet-corbet-ch) (module
naming, secrets-as-`*File`-options, no hardcoded domain/hostname/IP
anywhere in this repo).

## License

MIT.
