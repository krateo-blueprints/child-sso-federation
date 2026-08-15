#!/usr/bin/env python3
"""openstack-sso-bridge — basic-auth Krateo identity -> Horizon SSO.

Basic-auth portal users hold no Keycloak session, and Keystone has no basic-auth
federation protocol. This bridge mints a NATIVE Keystone token for the caller's
mapped tenant identity and injects it into Horizon through the SAME WebSSO
callback contract Phase 1 uses: it returns an auto-submitting HTML form that
POSTs `token` to Horizon's trusted_dashboard (/auth/websso/). Horizon validates
the token against Keystone and starts a session. (Proven live: a native,
non-OIDC, project-scoped Keystone token yields HTTP 302 -> / + sessionid on
/auth/websso/.)

CALLER VERIFICATION (authoritative contract, confirmed against krateo-authn
0.24.0 source): the child portal SPA obtains a Krateo authn JWT from
`GET /basic/login` ({accessToken,user,groups,data}) and sends it as
`Authorization: Bearer <JWT>`. That JWT is the identity. It is an HS256 (HMAC,
symmetric) token signed with the shared secret JWT_SIGN_KEY (Secret jwt-sign-key,
the same secret authn signs with and snowplow validates with) — there is NO JWKS
and NO authn introspection endpoint (/me,/userinfo,/introspect all 404 by design).
So we verify the signature LOCALLY (stdlib HMAC — PyJWT is not in the image) and
read the `username` claim (== `sub`; iss == krateo.io). The minted Keystone token
is bound STRICTLY to that verified username; there is NO target-user parameter,
so this is not an open token oracle.

Env:
  JWT_SIGN_KEY       shared HS256 signing secret (from Secret jwt-sign-key key JWT_SIGN_KEY)
  JWT_ISSUER         expected iss claim (default: krateo.io)
  AUTH_COOKIE_NAME   optional cookie name to also accept the JWT from (default: none/off)
  KEYSTONE_AUTH_URL  Keystone v3, e.g. http://keystone-api.krateo-system.svc.cluster.local:5000/v3
  HORIZON_WEBSSO_URL trusted_dashboard, e.g. https://horizon.braghettos-krateo.krateo.dev/auth/websso/
  TENANT_CRED_DIR    dir with mounted per-tenant cred files (default: /etc/sso-bridge/tenants)
  LISTEN_PORT        default 8080
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape

JWT_SIGN_KEY = os.environ["JWT_SIGN_KEY"].encode()
JWT_ISSUER = os.environ.get("JWT_ISSUER", "krateo.io")
AUTH_COOKIE_NAME = os.environ.get("AUTH_COOKIE_NAME", "").strip()
KEYSTONE_AUTH_URL = os.environ["KEYSTONE_AUTH_URL"].rstrip("/")
HORIZON_WEBSSO_URL = os.environ["HORIZON_WEBSSO_URL"]
TENANT_CRED_DIR = os.environ.get("TENANT_CRED_DIR", "/etc/sso-bridge/tenants")
PORT = int(os.environ.get("LISTEN_PORT", "8080"))

# Keystone's stock sso_callback_template, minimal form. $host + $token filled in.
# NOTE: the auto-POST to Horizon /auth/websso/ is CROSS-ORIGIN (bridge host ->
# horizon host). Horizon does strict CSRF *Referer* checking on HTTPS and only
# trusts the Keystone origin (that's why the Phase 1 Keystone-driven callback
# works). A Referer from this bridge host is rejected -> websso bounces to the
# login page. We therefore suppress the Referer (meta + referrerpolicy + the
# Referrer-Policy response header below); the browser still sends the Origin
# header (Origin: <bridge> is accepted), so the POST succeeds. Verified live:
# with Referer present -> /auth/login/ (fail); with Referer suppressed -> / (ok).
CALLBACK = """<!DOCTYPE html>
<html><head><title>Signing in…</title>
  <meta name="referrer" content="no-referrer"/>
</head><body>
  <form id="sso" name="sso" action="{host}" method="post" referrerpolicy="no-referrer">
    Please wait…
    <input type="hidden" name="token" value="{token}"/>
    <noscript><input type="submit" value="Continue"/></noscript>
  </form>
  <script>window.onload=function(){{document.forms['sso'].submit();}}</script>
</body></html>"""


def _b64url_decode(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def verify_jwt(token):
    """Verify an HS256 Krateo authn JWT locally and return the username, or None.

    Checks: three segments, alg==HS256, HMAC-SHA256 signature over
    `header.payload` with JWT_SIGN_KEY (constant-time compare), exp/nbf with 5s
    leeway, and iss==JWT_ISSUER. Identity = the `username` claim (falls back to
    `sub`, which authn sets equal to username)."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    if header.get("alg") != "HS256":
        return None
    expected = hmac.new(JWT_SIGN_KEY, f"{header_b64}.{payload_b64}".encode(),
                        hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    now = time.time()
    exp = payload.get("exp")
    if exp is not None and now > float(exp) + 5:
        return None
    nbf = payload.get("nbf")
    if nbf is not None and now < float(nbf) - 5:
        return None
    if JWT_ISSUER and payload.get("iss") != JWT_ISSUER:
        return None
    return payload.get("username") or payload.get("sub")


def bearer_from(headers):
    """Extract the Krateo JWT from Authorization: Bearer (primary) or, if
    AUTH_COOKIE_NAME is set, from that cookie. Never from the query string."""
    auth = headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    if AUTH_COOKIE_NAME:
        cookie = headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == AUTH_COOKIE_NAME and v:
                return v.strip()
    return None


def verify_caller(headers):
    tok = bearer_from(headers)
    if not tok:
        return None
    return verify_jwt(tok)


def tenant_creds(username):
    """Map the authenticated portal identity -> that tenant's stored Keystone
    credential. One file per tenant at TENANT_CRED_DIR/<username>.json, keyed by
    the portal username the bridge sees in the JWT. Shape (either):
      {"app_cred_id": "...", "app_cred_secret": "..."}                (preferred)
      {"user_id": "...", "password": "...", "project_id": "..."}      (password grant)
    """
    # basename() hardens against any traversal even though username comes from a
    # signed claim.
    safe = os.path.basename(username)
    path = os.path.join(TENANT_CRED_DIR, f"{safe}.json")
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def _keystone_auth(body):
    req = urllib.request.Request(
        KEYSTONE_AUTH_URL + "/auth/tokens",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        tok = r.headers.get("X-Subject-Token")
        if not tok:
            raise RuntimeError("no X-Subject-Token in Keystone response")
        return tok


def mint_token(creds):
    """Mint a PROJECT-SCOPED Keystone token for the tenant credential via the
    Keystone v3 REST API (no service-catalog lookup needed — we only read the
    X-Subject-Token header). App credentials are inherently project-scoped."""
    if creds.get("app_cred_id"):
        body = {"auth": {"identity": {
            "methods": ["application_credential"],
            "application_credential": {
                "id": creds["app_cred_id"],
                "secret": creds["app_cred_secret"],
            }}}}
        return _keystone_auth(body)
    # password grant fallback (explicitly project-scoped)
    body = {"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "id": creds["user_id"], "password": creds["password"]}}},
        "scope": {"project": {"id": creds["project_id"]}}}}
    return _keystone_auth(body)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body, extra_headers=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/healthz", "/health"):
            return self._send(200, "text/plain", "ok")
        if path != "/horizon-sso":
            return self._send(404, "text/plain", "not found")
        user = verify_caller(self.headers)
        if not user:
            return self._send(401, "text/plain",
                              "unauthenticated (no valid Krateo Bearer JWT)")
        creds = tenant_creds(user)
        if not creds:
            return self._send(403, "text/plain",
                              f"no OpenStack tenant mapping for {user}")
        try:
            token = mint_token(creds)
        except Exception as exc:
            print(f"[bridge] mint failed for {user}: {exc}", file=sys.stderr, flush=True)
            return self._send(502, "text/plain", "token mint failed")
        html = CALLBACK.format(host=escape(HORIZON_WEBSSO_URL, quote=True),
                               token=escape(token, quote=True))
        print(f"[bridge] minted scoped token for portal user {user} (len={len(token)})", flush=True)
        # Referrer-Policy: no-referrer so the cross-origin auto-POST to Horizon
        # carries no Referer (Horizon's strict CSRF referer check rejects the
        # untrusted bridge origin otherwise).
        self._send(200, "text/html; charset=utf-8", html,
                   {"Referrer-Policy": "no-referrer"})

    def log_message(self, fmt, *args):
        print("[bridge] " + (fmt % args), flush=True)


if __name__ == "__main__":
    print(f"[bridge] listening :{PORT} keystone={KEYSTONE_AUTH_URL} "
          f"horizon={HORIZON_WEBSSO_URL} iss={JWT_ISSUER} "
          f"cookie={AUTH_COOKIE_NAME or '(bearer-only)'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
