# child-sso-federation

Brings a freshly-provisioned Krateo **child** up **fully SSO-federated with OpenStack**
— with zero manual steps — as an additional `vcluster.helm[]` entry installed inside the
child's `krateo-system` namespace.

It delivers, per tenant, idempotently and wave-sequenced via plain bootstrap Jobs (no Helm
hooks):

- **Keycloak IdP** (realm `krateo`, clients, https issuer) + **Keystone OIDC federation**
  (IdentityProvider / mapping / protocol, `keycloak` domain, `demo` project) + **Horizon WebSSO**.
- **basic-auth token-bridge**: verifies a Krateo authn JWT locally (HS256) and mints a native
  Keystone token → Horizon logs the user straight in (no second login).
- **step-up MFA** on the child apiserver: a Keycloak `browser-mfa` flow + a `kubernetes` public
  client + a demo user with TOTP, plus a `ValidatingAdmissionPolicy` requiring `acr=2` (a fresh
  second factor) to DELETE a `composition.krateo.io` — enforced against the child's own apiserver
  (paired with `selfservice-krateo` ≥ 0.2.4 which wires `--authentication-config`).

## Publish (CI only — never `helm push` locally)
Merge to `main`, then push a semver tag from `main`:

```
git tag 0.1.1 && git push origin 0.1.1
```

`.github/workflows/release-oci.yaml` packages `chart/` and publishes
`oci://ghcr.io/braghettos/charts/child-sso-federation:<tag>`. `chart/Chart.yaml` keeps the
`CHART_VERSION` placeholder; CI rewrites it to the tag. A freshly created ghcr package defaults
to **private** — flip it to public once.

## Consumed by
`selfservice-krateo` (oci://ghcr.io/braghettos/charts/selfservice-krateo) references this chart
in its Vcluster CR init-helm list when `childKrateo.ssoFederation.enabled`.

## Known issue: GKE resizes the control plane during a first install
GKE can resize a new cluster's control plane unrequested, about 30 minutes after it is created. If that
happens mid-install, a component's composition controller can lose its lease and report
`HooksMayNotHaveRun`, and its release stays wedged. The recovery documented by openstack-as-a-service
0.3.74 is to set `rerunHooks.<component>: "<timestamp>"` on the child's `Openstack` spec, which runs that
component's hooks again. core-provider **2.13.128** and later recover an interrupted fresh install by
themselves (krateo-platformops/core-provider#629): the half-installed release is uninstalled without hooks
and installed again, at most 3 times, then it falls back to the human gate. The annotation
`krateo.io/interrupted-install-recovery` turns this off for a chart whose install hooks can't safely
repeat. A child on an older core-provider still needs the manual recovery above.

## Known follow-ups
- Declarative MFA: replace the imperative `55-job-mfa-bootstrap` + `files/mfa/build-*.py` with
  `keycloak.ogen.krateo.io` CRs once the KOG RestDefinition gaps close
  (braghettos/krateo-keycloak-operator-kog#6).
- RBAC-gap fixes for two wait-loops (deployments/secrets read) — see repo issues.
