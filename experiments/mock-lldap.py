#!/usr/bin/env python3
"""mock-lldap.py -- a throwaway stand-in for lldap's own HTTP API, used ONLY to exercise the
real, Nix-generated modules/lldap-reconcile.nix script offline, without ever touching a live
lldap. See experiments/README.md (this same repo) for why this exists at all and what it proved.

Implements exactly the two endpoints and the handful of GraphQL operations
modules/lldap-reconcile.nix's own script calls, in the exact request/response shapes learned from
lldap's own upstream schema.graphql + scripts/bootstrap.sh (see modules/lldap-reconcile.nix's
header for the precise citations):

  POST /auth/simple/login          {"username","password"} -> {"token": "..."}
  POST /api/graphql                dispatches on the query TEXT (this mock's whole state machine
                                    is a handful of exact, known query/mutation strings, since
                                    this is the one script that calls it, not a general lldap
                                    clone)

Plus three endpoints that are NOT part of lldap's own API at all, only this test's own
introspection: GET /_state (dump current in-memory state as JSON), GET /_calls (the ordered list
of MUTATION calls made since the last reset), POST /_reset_calls (clear that list without
touching the underlying user/group state -- this is what makes "run twice, prove zero mutations
the second time" checkable at all), POST /_seed (replace the entire in-memory state, JSON body).

Deliberately not a generalized lldap emulator: string-matching the query text is fragile and
would break instantly against any GraphQL client (this repo's own bootstrap-tool caveat, or a
human at a laptop) -- it is exactly precise enough for the one script that talks to it.
"""
import http.server
import json
import socketserver
import sys
import threading

EXPECTED_USER = "admin"
EXPECTED_PASS = "test-admin-password"

lock = threading.Lock()
state = {"users": {}, "groups": {}, "next_group_id": 1}
calls = []


def group_obj(name):
    g = state["groups"][name]
    return {"id": g["id"], "displayName": name}


def user_obj(u):
    return {
        "id": u["id"],
        "displayName": u["displayName"],
        "email": u["email"],
        "groups": [group_obj(g) for g in sorted(u["groups"])],
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output readable; the harness reads /_calls instead

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw) if raw else {}

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        with lock:
            if self.path == "/auth/simple/login":
                b = self._body()
                if b.get("username") == EXPECTED_USER and b.get("password") == EXPECTED_PASS:
                    self._send(200, {"token": "mock-bearer-token"})
                else:
                    self._send(401, {"error": "invalid credentials"})
                return

            if self.path == "/_seed":
                global state, calls
                state = self._body()
                calls = []
                self._send(200, {"ok": True})
                return

            if self.path == "/_reset_calls":
                calls.clear()
                self._send(200, {"ok": True})
                return

            if self.path == "/api/graphql":
                self._graphql(self._body())
                return

        self._send(404, {"error": "unknown path"})

    def do_GET(self):
        with lock:
            if self.path == "/_state":
                self._send(200, state)
                return
            if self.path == "/_calls":
                self._send(200, calls)
                return
        self._send(404, {"error": "unknown path"})

    def _graphql(self, body):
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer mock-bearer-token":
            self._send(200, {"errors": [{"message": "unauthenticated"}]})
            return

        q = body.get("query", "")
        v = body.get("variables", {}) or {}

        # ── top-level queries: matched on their exact prefix, see module docstring ───────────
        if q.startswith("query{users("):
            self._send(200, {"data": {"users": [user_obj(u) for u in state["users"].values()]}})
            return

        if q.startswith("query{groups{"):
            self._send(200, {"data": {"groups": [group_obj(n) for n in state["groups"]]}})
            return

        # ── mutations ─────────────────────────────────────────────────────────────────────────
        if "createGroup(" in q:
            name = v["n"]
            if name not in state["groups"]:
                state["groups"][name] = {"id": state["next_group_id"]}
                state["next_group_id"] += 1
            calls.append({"op": "createGroup", "name": name})
            self._send(200, {"data": {"createGroup": {"id": state["groups"][name]["id"]}}})
            return

        if "createUser(" in q:
            u = v["u"]
            uid = u["id"]
            if uid not in state["users"]:
                state["users"][uid] = {
                    "id": uid,
                    "displayName": u.get("displayName", ""),
                    "email": u.get("email", ""),
                    "groups": [],
                }
                calls.append({"op": "createUser", "id": uid})
                self._send(200, {"data": {"createUser": {"id": uid}}})
            else:
                self._send(200, {"errors": [{"message": f"user {uid} already exists"}]})
            return

        if "addUserToGroup(" in q:
            uid, gid = v["u"], v["g"]
            gname = next((n for n, g in state["groups"].items() if g["id"] == gid), None)
            if uid in state["users"] and gname is not None:
                if gname not in state["users"][uid]["groups"]:
                    state["users"][uid]["groups"].append(gname)
                calls.append({"op": "addUserToGroup", "user": uid, "group": gname})
                self._send(200, {"data": {"addUserToGroup": {"ok": True}}})
            else:
                self._send(200, {"errors": [{"message": "no such user or group"}]})
            return

        if "deleteUser(" in q:
            uid = v["u"]
            if uid in state["users"]:
                del state["users"][uid]
                calls.append({"op": "deleteUser", "id": uid})
                self._send(200, {"data": {"deleteUser": {"ok": True}}})
            else:
                self._send(200, {"errors": [{"message": f"user {uid} does not exist"}]})
            return

        self._send(200, {"errors": [{"message": f"mock-lldap: unrecognised query: {q}"}]})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main():
    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    # The one line the harness script parses -- printed and flushed before serving, so a caller
    # reading this process's stdout line-by-line can proceed the instant the port is known.
    print(f"MOCK_LLDAP_PORT={port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
