#!/usr/bin/env python3
import json, os, urllib.request, urllib.error
BASE=os.environ["KC_BASE"].rstrip("/"); REALM=os.environ.get("REALM","krateo")
TOKEN=os.environ["ADMIN_TOKEN"]; FID=os.environ["BROWSER_MFA_FLOW_ID"]
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

# delete existing kubernetes client if present
s,clients,_=call("GET","/clients?clientId=kubernetes")
if isinstance(clients,list):
    for c in clients:
        call("DELETE",f"/clients/{c['id']}"); print(f"deleted existing kubernetes client {c['id']}")

body={
 "clientId":"kubernetes","name":"Kubernetes (child apiserver OIDC, step-up)","enabled":True,
 "protocol":"openid-connect","publicClient":True,"standardFlowEnabled":True,
 "directAccessGrantsEnabled":True,"implicitFlowEnabled":False,
 "redirectUris":["http://localhost:8000","http://localhost:8000/*"],"webOrigins":["+"],
 "attributes":{"access.token.lifespan":"300"},
 "authenticationFlowBindingOverrides":{"browser":FID},
}
s,b,loc=call("POST","/clients",body); print(f"create kubernetes client -> {s}")
if s>=300: raise SystemExit(b)
cid=loc.rstrip("/").split("/")[-1]; print("client uuid:",cid)

# groups mapper
gm={"name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
    "config":{"claim.name":"groups","full.path":"false","id.token.claim":"true",
              "access.token.claim":"true","userinfo.token.claim":"true"}}
s,b,_=call("POST",f"/clients/{cid}/protocol-mappers/models",gm); print(f"add groups mapper -> {s}")
if s>=300 and "exists" not in str(b): raise SystemExit(b)

# verify
s,c,_=call("GET",f"/clients/{cid}")
print("verify: publicClient=",c["publicClient"],"directAccessGrants=",c["directAccessGrantsEnabled"],
      "standardFlow=",c["standardFlowEnabled"])
print("       flowBinding.browser=",c.get("authenticationFlowBindingOverrides",{}).get("browser"))
print("       access.token.lifespan=",c.get("attributes",{}).get("access.token.lifespan"))
