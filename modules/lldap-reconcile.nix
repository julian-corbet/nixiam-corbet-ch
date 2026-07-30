# modules/lldap-reconcile.nix — converge a running lldap directory's users and group
# memberships to `nixiam.users`, declaratively, on a hub timer.
#
# THE PRECEDENT THIS FOLLOWS. Same shape as a sibling repo's own
# `netbird-group-reconcile.nix`: a timer reads a running service's live objects over that
# service's own management API, diffs them against a Nix-declared table, and creates whatever
# the declaration says should exist and the live service does not have yet. Nothing here
# invents a new reconciliation idea; the one genuinely new decision this file makes, on top of
# that precedent, is in "WHAT IT NEVER DOES" below, and it exists because the thing being
# reconciled here is not a routing group, it is a human's ability to log in anywhere at all.
#
# WHAT IT TOUCHES. `nixiam.users.<name>` (modules/users.nix, this repo) is the sole input.
# Each declared, `enable = true` entry gets: an lldap account if one does not already exist
# (`createUser`), an lldap group for each declared membership if it does not already exist
# (`createGroup`), and that membership itself if it is not already present (`addUserToGroup`).
# All three are pure creation — the exact same additive-only posture `netbird-group-reconcile.nix`
# holds for group membership, extended here to account and group EXISTENCE too, because lldap
# groups (unlike NetBird's) carry no external policy references that a recreated object could
# orphan — see the group-creation step below for that comparison spelled out where it matters.
#
# WHAT IT NEVER DOES, AND WHY THIS IS THE LOAD-BEARING DECISION IN THIS FILE. lldap sits behind
# this fleet's SSO: removing a directory entry does not tidy up one service, it locks that human
# out of every service behind that SSO simultaneously, with no automatic undo once the mutation
# lands. So an lldap user or membership this table does not (or no longer) declare is NEVER
# removed by this service. Ever. By default. Full stop. It is reported — loudly, every tick, as a
# non-zero exit and a WARN line naming exactly what is undeclared — and left completely alone.
# This mirrors a decision this same nix* family already made for exactly this reason:
# `nixiac`'s own control plane inverts Crossplane's own default management policy from
# "observe, create, update, delete" to "observe only, orphan on removal" specifically because the
# destructive action must be asked for, in writing, rather than inherited as a framework default.
# The ONE way to still get a real deletion out of this service is `nixiam.users.<name>`'s own
# `acknowledgeRemoval` — a written reason, required, living on the declaration this module reads,
# never a flag on this module itself; see modules/users.nix's own description of that option for
# why deletion belongs on the per-person declaration and not as a blanket switch here.
#
# WHAT IT LEAVES ALONE, EVEN AMONG THINGS IT MANAGES. Passwords, TOTP secrets, sessions,
# last-login — lldap's OWN state, never touched, never even queried; see modules/users.nix's
# header for the full CONFIGURATION-vs-STATE line this whole repo holds to. Any group NOT named
# by a declared user's `groups` list (lldap's own built-in `lldap_admin`/`lldap_password_manager`/
# `lldap_strict_readonly` groups among them — confirmed to exist by name only, from that trio
# being excluded by lldap's own `scripts/bootstrap.sh` when it computes "redundant" groups to
# prune, never independently audited for their exact per-mutation ACL scope here — see this
# module's own `adminUsername` option for the one place that gap actually matters). An EXTRA
# membership lldap has that the declaration does not (reported, never removed — see the
# drift-reporting step). Update of an already-existing user's `displayName`/`email` on drift —
# deliberately NOT done: this module only ever creates what is missing, the identical
# once-then-hands-off posture `lldap.nix`'s own `adminPasswordFile` in this repo already commits
# to (read once at first start, never re-applied, because "the running directory is the source of
# truth from then on" — see that option's description). Re-litigating that choice for
# displayName/email is `experiments/README.md`'s own open question, not a decision made here.
#
# ── WHERE THE lldap API FACTS BELOW WERE LEARNED, SPECIFICALLY ─────────────────────────────────
#
# lldap exposes ONE stable API surface for everything this module does: a plain REST login
# endpoint that mints a short-lived bearer token, and a GraphQL endpoint behind it for everything
# else. Both read directly from lldap's own upstream repository (github.com/lldap/lldap),
# checked 2026-07-30:
#
#   - `schema.graphql` (repo root) — the full GraphQL schema. Confirms every mutation and query
#     this module calls: `createUser(user: CreateUserInput!): User!`, `createGroup(name: String!):
#     Group!`, `addUserToGroup(userId: String!, groupId: Int!): Success!`, `deleteUser(userId:
#     String!): Success!`, `users(filters: RequestFilter): [User!]!`, `groups: [Group!]!`. It also
#     confirms the one fact this module's entire safety argument for a Nix-declared credential
#     rests on: `CreateUserInput` and `UpdateUserInput` have NO password field of any kind. lldap's
#     GraphQL API is structurally incapable of accepting a password through the mutations this
#     module calls — not a convention this script follows, a thing the schema does not expose at
#     all. (Password changes go through a completely separate SRP-like protocol and a dedicated
#     `lldap_set_password` tool, per that repo's own `scripts/bootstrap.sh` — genuinely a different
#     mechanism, not merely a different option, which is exactly why modules/users.nix has no
#     password field to be tempted to wire up.)
#   - `scripts/bootstrap.sh` (repo root) — lldap's own official bootstrap tool, source of the
#     REST auth flow (`auth()`: `POST {url}/auth/simple/login` with a JSON `{username, password}`
#     body, response `.token` is the bearer token), the GraphQL call shape (`make_query()`: `POST
#     {url}/api/graphql`, `Authorization: Bearer $TOKEN`), and — the detail this module's own
#     idempotency rests on — the check-before-mutate pattern its own `create_user`/`create_group`/
#     `add_user_to_group` functions all use (`user_exists`/`group_exists`/`user_in_group` queried
#     first, the mutation only fired if the check says the target state does not already hold).
#     This module's shell script below follows the identical discipline, for the identical reason:
#     lldap's own official bootstrap tool does not trust `createUser`/`createGroup` to be silently
#     idempotent on their own, so neither does this one.
#
# ── CREDENTIAL: WHY IT CANNOT BE A NIX-STORE PATH, AND WHY IT IS RE-READ EVERY RUN ─────────────
#
# `credentialFile` holds `adminUsername`'s plaintext password, read fresh at the start of every
# run to mint a new short-lived bearer token — lldap issues a JWT with a TTL through the login
# endpoint above, not a long-lived API key, so there is no token to cache in the first place; only
# the same password, every time. Asserted below to never resolve inside the Nix store: the store
# is world-readable on every machine that has ever built this configuration, and this credential
# can create and read every directory entry lldap holds — landing it in the store does not make it
# "less protected", it PUBLISHES it, permanently, to every local account on every one of those
# machines. See modules/users.nix's own header for the identical argument applied to the registry
# this module reads.
#
# ── WHY THIS RUNS AS ROOT, WITH NO DynamicUser/LoadCredential, MATCHING TWO EXISTING PRECEDENTS ──
#
# Neither `nixstorage.reconciler`'s own `systemd.services.nixstorage-reconcile` nor this repo's
# sibling `netbird-group-reconcile.nix` sandboxes its unit beyond systemd's own default (no
# `User=`, no `DynamicUser`) — both reason that the one thing the unit needs (reading a
# root-owned runtime secret file) is exactly what a hardening profile would take away. This module
# follows the same default for the same reason, UNVERIFIED rather than silently assumed: whether
# `credentialFile`'s real-world permissions would even allow a narrower, non-root reader has not
# been checked against a real deployment — see `experiments/README.md` for this flagged as open
# rather than quietly decided either way.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.nixiam.lldapReconcile;
  users = config.nixiam.users or { };

  runtimeBin = lib.makeBinPath [
    pkgs.curl
    pkgs.jq
    pkgs.coreutils # cat, mktemp, sleep, printf, rm
    pkgs.gnugrep # grep -qxF, used only in the drift/prune lookup below
  ];

  ensureUsers = filterAttrs (_: u: u.enable) users;
  pruneAcknowledged = attrNames (filterAttrs (_: u: !u.enable && u.acknowledgeRemoval != null) users);

  # The ONE flat JSON document this module hands its script -- Nix resolves and validates
  # everything at eval time (the `nixiam.users` assertions in modules/users.nix already ran by
  # the time this is built), the script consumes an already-correct document and contains no
  # Nix-shaped logic of its own. Same split this whole nix* family uses throughout
  # (nixnet's config.json, nixshare's watchdog.json, nixstorage's own reconcile.json).
  renderedModel = {
    ensure = mapAttrs
      (_: u: { inherit (u) displayName email groups; })
      ensureUsers;
    pruneAcknowledged = pruneAcknowledged;

    # Groups the directory must have EVEN IF NOBODY IS IN THEM. Unioned with the
    # membership-derived set below rather than replacing it, because both are real: a group can be
    # live because someone is in it, or live because an application maps a role onto it, and the
    # second kind is invisible from here (that mapping lives in the app's own config, often sealed).
    # A zero-member group is not a dead one.
    # Read defensively: this module is the MECHANISM and users.nix is the REGISTRY, and a host may
    # import one without the other. Same idiom every cross-module read in this family uses.
    standaloneGroups = attrNames (config.nixiam.lldapGroups or { });
  };

  modelFile = pkgs.writeText "nixiam-lldap-reconcile-model.json" (builtins.toJSON renderedModel);

  reconcile = pkgs.writeShellScript "nixiam-lldap-reconcile" ''
    #!${pkgs.runtimeShell}
    # No `set -e`: one failed mutation against one declared person, or one API hiccup fetching
    # current state, must not abort handling of every OTHER declared person queued behind it in
    # the same run. Every failure path below is handled explicitly; the default on ANY doubt is
    # "leave the directory exactly as it is, log why, let the next tick retry" -- never a partial
    # apply and never, under any condition this script can reach on its own, a deletion outside
    # the one explicit prune path below.
    set -uo pipefail
    export PATH=${runtimeBin}:$PATH

    API=${lib.escapeShellArg cfg.apiUrl}
    CREDFILE=${lib.escapeShellArg cfg.credentialFile}
    ADMINUSER=${lib.escapeShellArg cfg.adminUsername}
    MODEL=${lib.escapeShellArg modelFile}

    DRIFT=0
    log()  { echo "nixiam-lldap-reconcile: $*"; }
    warn() { echo "nixiam-lldap-reconcile: WARN: $*" >&2; DRIFT=1; }
    skip() { log "SKIP: $*"; exit 0; }

    [ -r "$CREDFILE" ] || skip "credential file $CREDFILE not readable yet (secrets provisioning not done)"
    PASSWORD=$(cat "$CREDFILE")
    [ -n "$PASSWORD" ] || skip "empty credential in $CREDFILE"
    [ -r "$MODEL" ] || skip "model $MODEL not present"

    AUTH_F=$(mktemp); USERS_F=$(mktemp); GROUPS_F=$(mktemp)
    trap 'rm -f "$AUTH_F" "$USERS_F" "$GROUPS_F"' EXIT

    # ── auth: POST /auth/simple/login -> {token}. See this module's header for exactly where
    # this endpoint and its request/response shape were learned (lldap's own bootstrap.sh). ────
    login_body=$(jq -n --arg u "$ADMINUSER" --arg p "$PASSWORD" '{username:$u,password:$p}')
    if ! curl -fsS --max-time 20 -X POST "$API/auth/simple/login" \
          -H 'Content-Type: application/json' -d "$login_body" -o "$AUTH_F"; then
      skip "POST $API/auth/simple/login failed -- lldap not reachable yet, or credential wrong"
    fi
    unset PASSWORD login_body
    TOKEN=$(jq -r '.token // empty' "$AUTH_F")
    [ -n "$TOKEN" ] || skip "no .token in login response -- credential likely wrong"

    gql() { # $1 = JSON request body, $2 = output file
      curl -fsS --max-time 20 -X POST "$API/api/graphql" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d "$1" -o "$2"
    }

    # ── fetch current state, retried, and floored: a transient bad response must be a clean
    # no-op, never a partial reconcile that would read as "everyone but the admin got deleted".
    # The admin account we just authenticated as is always present in a real directory, so an
    # empty users array is never a legitimate response -- same reasoning, same >=1 floor, as
    # this repo's own sibling netbird-group-reconcile.nix applies to a peer list. ────────────
    fetch_current() {
      local tries=0
      while [ "$tries" -lt 4 ]; do
        if gql '{"query":"query{users(filters:null){id displayName email groups{id displayName}}}"}' "$USERS_F" \
           && jq -e '.data.users|type=="array"' "$USERS_F" >/dev/null 2>&1 \
           && gql '{"query":"query{groups{id displayName}}"}' "$GROUPS_F" \
           && jq -e '.data.groups|type=="array"' "$GROUPS_F" >/dev/null 2>&1; then
          local n; n=$(jq '.data.users|length' "$USERS_F" 2>/dev/null || echo 0)
          [ "$n" -ge 1 ] 2>/dev/null && return 0
        fi
        tries=$((tries + 1)); sleep 2
      done
      return 1
    }
    fetch_current || skip "could not fetch a sane users/groups snapshot after retries -- refusing to reconcile (would risk treating a bad response as a mass deletion)"

    group_id_for()  { jq -r --arg n "$1" '.data.groups[] | select(.displayName==$n) | .id' "$GROUPS_F"; }
    user_exists()   { jq -e --arg id "$1" '.data.users[] | select(.id==$id)' "$USERS_F" >/dev/null 2>&1; }
    user_in_group() { jq -e --arg id "$1" --arg g "$2" '.data.users[] | select(.id==$id) | .groups[]? | select(.displayName==$g)' "$USERS_F" >/dev/null 2>&1; }
    mutation_error() { jq -r '.errors | if . != null then (.[0].message // "unknown error") else empty end' "$1" 2>/dev/null; }

    declared_ids=$(jq -r '.ensure | keys[]' "$MODEL")
    prune_ids=$(jq -r '.pruneAcknowledged[]' "$MODEL")

    # ── 1. groups: create any group that is declared -- either named by a declared person's
    # membership list, or declared standalone in nixiam.lldapGroups because an application maps a
    # role onto it while it currently holds no members.
    # `createGroup` is lldap's own idempotent-by-check create-by-display-name mutation (see
    # header). Auto-creating here, rather than only warning the way netbird-group-reconcile.nix
    # does for a MISSING NetBird group, is deliberate and NOT the same call made twice: a NetBird
    # group's id is referenced by ACL policies that a recreate would orphan; an lldap group
    # carries no such external reference, and lldap's own official bootstrap.sh creates missing
    # groups on sight for exactly that reason. ──────────────────────────────────────────────────
    wanted_groups=$(jq -r '([.ensure[].groups[]] + .standaloneGroups) | unique | .[]' "$MODEL")
    if [ -n "$wanted_groups" ]; then
      while IFS= read -r g; do
        [ -n "$g" ] || continue
        if [ -z "$(group_id_for "$g")" ]; then
          resp=$(mktemp)
          gql "$(jq -n --arg n "$g" '{query:"mutation($n:String!){createGroup(name:$n){id}}",variables:{n:$n}}')" "$resp"
          err=$(mutation_error "$resp")
          if [ -n "$err" ]; then warn "creating group '$g' failed: $err"
          else log "created missing group '$g'"; fi
          rm -f "$resp"
        fi
      done <<< "$wanted_groups"
      fetch_current || skip "could not re-fetch state after creating missing groups"
    fi

    # ── 2. users: create any declared person absent from lldap. CreateUserInput has no password
    # field at all (see header) -- structurally, not by this script's own restraint. ──────────
    if [ -n "$declared_ids" ]; then
      while IFS= read -r id; do
        [ -n "$id" ] || continue
        if ! user_exists "$id"; then
          dn=$(jq -r --arg n "$id" '.ensure[$n].displayName' "$MODEL")
          em=$(jq -r --arg n "$id" '.ensure[$n].email' "$MODEL")
          resp=$(mktemp)
          gql "$(jq -n --arg id "$id" --arg dn "$dn" --arg em "$em" \
                  '{query:"mutation($u:CreateUserInput!){createUser(user:$u){id}}",variables:{u:{id:$id,displayName:$dn,email:$em}}}')" "$resp"
          err=$(mutation_error "$resp")
          if [ -n "$err" ]; then warn "creating user '$id' failed: $err"
          else log "created missing user '$id'"; fi
          rm -f "$resp"
        fi
      done <<< "$declared_ids"
      fetch_current || skip "could not re-fetch state after creating missing users"
    fi

    # ── 3. memberships: add any declared membership lldap does not have yet. ─────────────────
    if [ -n "$declared_ids" ]; then
      while IFS= read -r id; do
        [ -n "$id" ] || continue
        wanted=$(jq -r --arg n "$id" '.ensure[$n].groups[]' "$MODEL")
        [ -n "$wanted" ] || continue
        while IFS= read -r g; do
          [ -n "$g" ] || continue
          gid=$(group_id_for "$g")
          if [ -z "$gid" ]; then
            warn "group '$g' still missing after create attempt -- skipping membership for '$id'"
            continue
          fi
          if ! user_in_group "$id" "$g"; then
            resp=$(mktemp)
            gql "$(jq -n --arg u "$id" --argjson g "$gid" '{query:"mutation($u:String!,$g:Int!){addUserToGroup(userId:$u,groupId:$g){ok}}",variables:{u:$u,g:$g}}')" "$resp"
            err=$(mutation_error "$resp")
            if [ -n "$err" ]; then warn "adding '$id' to group '$g' failed: $err"
            else log "added '$id' to group '$g'"; fi
            rm -f "$resp"
          fi
        done <<< "$wanted"
      done <<< "$declared_ids"
    fi

    # ── 4./5. drift: every lldap user NOT declared (`ensure`). Exactly two outcomes -- an
    # explicit, per-person, written-reason acknowledgement deletes; anything else, including a
    # name this registry has never heard of, is reported and left untouched, forever. See this
    # module's header for why there is no third option. An already-declared user's EXTRA
    # (undeclared) group memberships are reported the same way, never removed. ────────────────
    current_ids=$(jq -r '.data.users[].id' "$USERS_F")
    if [ -n "$current_ids" ]; then
      while IFS= read -r id; do
        [ -n "$id" ] || continue
        if jq -e --arg id "$id" '.ensure | has($id)' "$MODEL" >/dev/null 2>&1; then
          while IFS= read -r g; do
            [ -n "$g" ] || continue
            if ! jq -e --arg id "$id" --arg g "$g" '.ensure[$id].groups | index($g) != null' "$MODEL" >/dev/null 2>&1; then
              warn "lldap user '$id' is a member of group '$g', which nixiam.users.\"$id\".groups does not declare -- left untouched (membership removal is never automatic)"
            fi
          done < <(jq -r --arg id "$id" '.data.users[] | select(.id==$id) | .groups[]?.displayName' "$USERS_F")
          continue
        fi
        if printf '%s\n' "$prune_ids" | grep -qxF "$id"; then
          resp=$(mktemp)
          gql "$(jq -n --arg u "$id" '{query:"mutation($u:String!){deleteUser(userId:$u){ok}}",variables:{u:$u}}')" "$resp"
          err=$(mutation_error "$resp")
          if [ -n "$err" ]; then warn "deleting acknowledged-removal user '$id' failed: $err"
          else log "deleted acknowledged-removal user '$id' (nixiam.users.\"$id\".enable = false, acknowledgeRemoval set)"; fi
          rm -f "$resp"
        else
          warn "lldap user '$id' is not declared in nixiam.users (or is declared with enable = false and no acknowledgeRemoval) -- left untouched. Add it to nixiam.users, or set acknowledgeRemoval on it to remove it deliberately."
        fi
      done <<< "$current_ids"
    fi

    if [ "$DRIFT" = 1 ]; then
      log "reconcile finished WITH drift or errors reported above"
      exit 1
    else
      log "reconcile finished, no drift, nothing left to do"
      exit 0
    fi
  '';

  storeDir = builtins.storeDir;
in
{
  options.nixiam.lldapReconcile = {
    enable = mkEnableOption ''
      the lldap directory reconciler: a systemd oneshot (+ timer) that
      converges a running lldap instance's users and group memberships to
      nixiam.users -- see modules/lldap-reconcile.nix's own header for
      exactly what it creates and what it structurally refuses to delete
    '';

    apiUrl = mkOption {
      type = types.str;
      default = "http://127.0.0.1:17170";
      example = "http://127.0.0.1:17170";
      description = ''
        Base URL of lldap's own HTTP API -- matches `nixiam.lldap.httpHost`/
        `httpPort`'s own defaults in this repo when this reconciler runs
        co-located with the lldap it manages (the common case). GraphQL
        lives at `<apiUrl>/api/graphql`; the login endpoint at
        `<apiUrl>/auth/simple/login` -- both confirmed against lldap's own
        `scripts/bootstrap.sh`, see this module's header. A wrong value here
        fails loudly and immediately (every run logs `SKIP: POST
        .../auth/simple/login failed`) rather than silently reconciling
        nothing -- there is no default that could be silently wrong instead,
        since a bad URL simply never connects.
      '';
    };

    adminUsername = mkOption {
      type = types.str;
      default = "admin";
      description = ''
        lldap account name whose password `credentialFile` holds -- must be
        one lldap authorizes to call `createUser`/`createGroup`/
        `addUserToGroup`/`deleteUser`. lldap's own admin account always can.
        Whether a narrower built-in group (`lldap_password_manager`) also
        suffices for every mutation this module calls was NOT independently
        verified here -- only that lldap ships that group by name, from it
        being excluded as "not redundant" in lldap's own `scripts/
        bootstrap.sh`; see this module's header. Use the admin account
        unless you have confirmed a narrower one covers every mutation
        above against a real lldap instance.
      '';
    };

    credentialFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing `adminUsername`'s plaintext password, read
        fresh at the start of every reconcile run. NEVER a path inside the
        Nix store -- asserted below, because the store is world-readable on
        every machine that has ever built this configuration, and this
        credential can create and read every directory entry lldap holds.
        No default: provisioning a real secret here is entirely your
        responsibility, the same posture `nixiam.lldap`'s own
        `jwtSecretFile`/`adminPasswordFile` in this repo already hold to.

        Why this is re-read every run instead of a cached token being
        provisioned once: lldap's login endpoint mints a short-lived JWT,
        not a long-lived API key, so there is nothing stable to cache in
        the first place except the same password -- caching a token would
        just be a second plaintext secret with an expiry nobody is
        watching, not a safer version of the same thing.
      '';
    };

    dependsOnUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Extra systemd units this reconciler depends on -- typically
        whatever unit provisions `credentialFile` (a sops-nix/agenix
        activation, a secrets-fetch service), and `lldap.service` itself
        when this reconciler runs co-located with it. Wired into both
        `after` and `requires` below, same reasoning as `nixiam.lldap`'s
        own `dependsOnUnits` in this repo: `after` alone only delays this
        unit relative to that one, it does not verify the dependency
        actually reached an active state first. Left empty by default
        because this reconciler CAN run against a remote lldap on a
        different host, where there is no local unit to depend on at all.
      '';
    };

    onBootSec = mkOption {
      type = types.str;
      default = "5min";
      description = "Delay after boot before the first reconcile.";
    };

    interval = mkOption {
      type = types.str;
      default = "30min";
      description = ''
        `OnUnitActiveSec` between reconciles. Declared humans change far
        less often than the netbird peer list this timer shape was copied
        from (see this module's header), so 30 minutes trades promptness
        for not hammering lldap's own admin API on a cadence nothing here
        needs.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(lib.hasPrefix storeDir (toString cfg.credentialFile));
        message = ''
          nixiam.lldapReconcile.credentialFile ("${toString cfg.credentialFile}") resolves inside
          the Nix store (${storeDir}). Everything the store holds is world-readable on every
          machine that has ever built this configuration -- an lldap admin credential landing
          there is not "less protected", it is published to every local account on every one of
          those machines, permanently (a store path referenced anywhere never truly disappears).
          Point this at a runtime secret path instead (sops-nix/agenix's own decrypted-at-boot
          output, a systemd credential, anything outside the store) -- the same posture
          nixiam.lldap.adminPasswordFile in this same repo already holds to.
        '';
      }
    ];

    environment.etc."nixiam/lldap-reconcile-model.json".source = modelFile;

    systemd.services.nixiam-lldap-reconcile = {
      description = "Reconcile lldap users/groups from nixiam.users";
      after = [ "network-online.target" ] ++ cfg.dependsOnUnits;
      wants = [ "network-online.target" ];
      requires = cfg.dependsOnUnits;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${reconcile}";
        MemoryMax = "128M";
        TimeoutStartSec = "5min";
      };
      unitConfig.StartLimitIntervalSec = 0;
    };

    systemd.timers.nixiam-lldap-reconcile = {
      description = "Periodic trigger for nixiam-lldap-reconcile.service";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = cfg.onBootSec;
        OnUnitActiveSec = cfg.interval;
        RandomizedDelaySec = "1min";
        Persistent = true;
      };
    };
  };
}
