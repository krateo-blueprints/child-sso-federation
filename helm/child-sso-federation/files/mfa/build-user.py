#!/usr/bin/env python3
import json, os, urllib.request, urllib.error
BASE=os.environ["KC_BASE"].rstrip("/"); REALM=os.environ.get("REALM","krateo")
TOKEN=os.environ["ADMIN_TOKEN"]; PW=os.environ["KC_PASS"]; TOTP=os.environ["TOTP_SECRET"]
USER=os.environ.get("KC_USER","braghettos"); GROUP=os.environ.get("GROUP_NAME","braghettos-admin")
R=f"{BASE}/admin/realms/{REALM}"; H={"Authorization":f"Bearer {TOKEN}","Content-Type":"application/json"}
def call(m,p,b=None):
    url=p if p.startswith("http") else R+p
    data=json.dumps(b).encode() if b is not None else None
    req=urllib.request.Request(url,data=data,headers=H,method=m)
    try:
        with urllib.request.urlopen(req) as r:
            raw=r.read(); return r.status,(json.loads(raw) if raw.strip() else None),r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code,e.read().decode(),None

# --- group ---
s,groups,_=call("GET",f"/groups?search={GROUP}")
gid=None
if isinstance(groups,list):
    for g in groups:
        if g["name"]==GROUP: gid=g["id"]
if not gid:
    s,b,loc=call("POST","/groups",{"name":GROUP}); print(f"create group {GROUP} -> {s}")
    gid=loc.rstrip("/").split("/")[-1]
print("group id:",gid)

# --- user (create if missing) ---
s,users,_=call("GET",f"/users?username={USER}&exact=true")
uid=users[0]["id"] if isinstance(users,list) and users else None
if not uid:
    s,b,loc=call("POST","/users",{"username":USER,"enabled":True,"email":f"{USER}@braghettos.krateo.dev",
        "firstName":"Braghettos","lastName":"Admin","emailVerified":True}); print(f"create user {USER} -> {s}")
    if s>=300: raise SystemExit(b)
    uid=loc.rstrip("/").split("/")[-1]
print("user id:",uid)

# --- OTP credential FIRST (raw secret, HmacSHA1/6/30 to match totp.py).
#     0.1.2 fix: a PUT /users/{id} with `credentials:[...]` REPLACES the whole credential
#     array, so enrolling OTP this way WIPES any password. Do OTP first, then set the
#     password via the dedicated reset-password endpoint (which ADDS a password without
#     touching OTP) LAST — so both survive and unattended login works. Also clear
#     requiredActions so no pending CONFIGURE_TOTP/UPDATE_PASSWORD blocks direct login. ---
cred={"type":"otp","userLabel":"stepup-totp",
      "secretData":json.dumps({"value":TOTP}),
      "credentialData":json.dumps({"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1"})}
# clear any existing otp first
s,creds,_=call("GET",f"/users/{uid}/credentials")
if isinstance(creds,list):
    for c in creds:
        if c["type"]=="otp": call("DELETE",f"/users/{uid}/credentials/{c['id']}")
s,b,_=call("PUT",f"/users/{uid}",{"credentials":[cred],"requiredActions":[]})
print(f"enrol OTP -> {s}")

# --- password LAST (authoritative from KC_PASS; reset-password ADDS a password
#     credential without removing the OTP) ---
s,b,_=call("PUT",f"/users/{uid}/reset-password",{"type":"password","value":PW,"temporary":False})
print(f"set password -> {s}")

# --- group membership ---
s,b,_=call("PUT",f"/users/{uid}/groups/{gid}")
print(f"add to group -> {s}")

# --- report ---
s,creds,_=call("GET",f"/users/{uid}/credentials")
print("credential types:",[c["type"] for c in creds] if isinstance(creds,list) else creds)
s,mg,_=call("GET",f"/users/{uid}/groups")
print("groups:",[g["path"] for g in mg] if isinstance(mg,list) else mg)
