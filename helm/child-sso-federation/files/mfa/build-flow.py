#!/usr/bin/env python3
import json, os, sys, urllib.request, urllib.error

BASE = os.environ["KC_BASE"].rstrip("/")   # e.g. http://127.0.0.1:18080
REALM = os.environ.get("REALM", "krateo")
TOKEN = os.environ["ADMIN_TOKEN"]
R = f"{BASE}/admin/realms/{REALM}"
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def call(method, path, body=None, expect=None):
    url = path if path.startswith("http") else R + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=H, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            loc = resp.headers.get("Location")
            return resp.status, (json.loads(raw) if raw.strip() else None), loc
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), None

def get(path):
    s, b, _ = call("GET", path)
    if s >= 300: raise SystemExit(f"GET {path} -> {s} {b}")
    return b

# --- 0. idempotent reuse. 0.1.4: a re-run must NOT delete+recreate the flow — it's
#     bound CLIENT-level to the `kubernetes` client, so DELETE 500s and the subsequent
#     create 409s -> the Job fails on every CDC re-run and the composition never
#     converges. The full ladder is built on the first successful run, so if the flow
#     already exists just emit its id and exit 0 (reuse). ---
flows = get("/authentication/flows")
existing = [f for f in flows if f["alias"] == "browser-mfa"]
if existing:
    print("BROWSER_MFA_FLOW_ID=" + existing[0]["id"])
    print("browser-mfa flow already exists -> reusing (idempotent)")
    sys.exit(0)

# --- 1. create top-level flow ---
s,b,_ = call("POST", "/authentication/flows", {
    "alias":"browser-mfa","description":"Browser flow with conditional 2nd factor (Krateo step-up)",
    "providerId":"basic-flow","topLevel":True,"builtIn":False})
print(f"create browser-mfa flow -> {s}")
if s>=300: raise SystemExit(b)

def add_exec(flow_alias, provider):
    s,b,_ = call("POST", f"/authentication/flows/{flow_alias}/executions/execution", {"provider":provider})
    print(f"  +exec {provider} in {flow_alias} -> {s}")
    if s>=300: raise SystemExit(b)

def add_subflow(flow_alias, alias, desc=""):
    s,b,_ = call("POST", f"/authentication/flows/{flow_alias}/executions/flow",
                 {"alias":alias,"type":"basic-flow","description":desc,"provider":"registration-page-form"})
    print(f"  +subflow {alias} in {flow_alias} -> {s}")
    if s>=300: raise SystemExit(b)

# --- 2. build ladder ---
add_exec("browser-mfa", "auth-cookie")
add_exec("browser-mfa", "identity-provider-redirector")
add_subflow("browser-mfa", "browser-mfa-forms", "Interactive forms (LoA ladder)")
add_subflow("browser-mfa-forms", "browser-mfa-loa1")
add_exec("browser-mfa-loa1", "conditional-level-of-authentication")
add_exec("browser-mfa-loa1", "auth-username-password-form")
add_subflow("browser-mfa-forms", "browser-mfa-loa2")
add_exec("browser-mfa-loa2", "conditional-level-of-authentication")
add_exec("browser-mfa-loa2", "auth-otp-form")

# --- 3. set requirements (walk the flat execution list) ---
def set_req(display_substr, level, requirement, provider=None, occurrence=0):
    execs = get("/authentication/flows/browser-mfa/executions")
    hits=[]
    for e in execs:
        dn = (e.get("displayName") or "")
        pv = e.get("providerId") or ""
        if e.get("level")==level and (provider is None or pv==provider) and (display_substr.lower() in dn.lower() or display_substr.lower() in (e.get("alias","") or "").lower()):
            hits.append(e)
    if not hits:
        raise SystemExit(f"no exec match {display_substr} lvl{level} prov{provider}")
    e = hits[occurrence]
    e["requirement"]=requirement
    s,b,_ = call("PUT", "/authentication/flows/browser-mfa/executions", e)
    print(f"  set {e.get('displayName') or e.get('alias')} lvl{level} -> {requirement} ({s})")
    if s>=300: raise SystemExit(b)
    return e

# top level
set_req("Cookie", 0, "ALTERNATIVE", provider="auth-cookie")
set_req("Identity Provider Redirector", 0, "DISABLED", provider="identity-provider-redirector")
set_req("browser-mfa-forms", 0, "ALTERNATIVE")
# subflows at level 1
set_req("browser-mfa-loa1", 1, "CONDITIONAL")
set_req("browser-mfa-loa2", 1, "CONDITIONAL")
# loa1 children (level 2)
set_req("Condition - level of authentication", 2, "REQUIRED", provider="conditional-level-of-authentication", occurrence=0)
set_req("Username Password Form", 2, "REQUIRED", provider="auth-username-password-form")
# loa2 children (level 2)
set_req("Condition - level of authentication", 2, "REQUIRED", provider="conditional-level-of-authentication", occurrence=1)
set_req("OTP Form", 2, "REQUIRED", provider="auth-otp-form")

# --- 4. authenticator config on the two conditional-LoA executions ---
def config_loa(occurrence, level_val, max_age):
    execs = get("/authentication/flows/browser-mfa/executions")
    cond=[e for e in execs if (e.get("providerId")=="conditional-level-of-authentication")]
    e=cond[occurrence]
    s,b,_ = call("POST", f"/authentication/executions/{e['id']}/config",
                 {"alias":f"loa{level_val}-condition","config":{"loa-condition-level":str(level_val),"loa-max-age":str(max_age)}})
    print(f"  config LoA level={level_val} max-age={max_age} on exec occ{occurrence} -> {s}")
    if s>=300: raise SystemExit(b)

config_loa(0, 1, 36000)
config_loa(1, 2, 0)

# --- 5. print final structure + flow id ---
flows = get("/authentication/flows")
fid=[f["id"] for f in flows if f["alias"]=="browser-mfa"][0]
print("BROWSER_MFA_FLOW_ID="+fid)
print("=== final browser-mfa structure ===")
for e in get("/authentication/flows/browser-mfa/executions"):
    print(f"lvl{e['level']} {e['requirement']:12} {(e.get('displayName') or e.get('alias') or '')[:40]:40} cfg={'Y' if e.get('authenticationConfig') else '-'}")
