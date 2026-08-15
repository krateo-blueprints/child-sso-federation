{{/*
Common name/label helpers.
*/}}
{{- define "child-sso.name" -}}child-sso-federation{{- end -}}

{{- define "child-sso.namespace" -}}
{{- .Values.namespace | default "krateo-system" -}}
{{- end -}}

{{- define "child-sso.labels" -}}
app.kubernetes.io/name: child-sso-federation
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: child-sso-federation-{{ .Chart.Version }}
{{- end -}}

{{/* -------- per-tenant host derivation (baseHost is REQUIRED) -------- */}}
{{- define "child-sso.baseHost" -}}
{{- required "baseHost is required (e.g. acme.krateo.dev)" .Values.baseHost -}}
{{- end -}}

{{- define "child-sso.host.keycloak" -}}
{{- .Values.hosts.keycloak | default (printf "keycloak.%s" (include "child-sso.baseHost" .)) -}}
{{- end -}}

{{- define "child-sso.host.keystone" -}}
{{- .Values.hosts.keystone | default (printf "keystone.%s" (include "child-sso.baseHost" .)) -}}
{{- end -}}

{{- define "child-sso.host.horizon" -}}
{{- .Values.hosts.horizon | default (printf "horizon.%s" (include "child-sso.baseHost" .)) -}}
{{- end -}}

{{- define "child-sso.host.portal" -}}
{{- .Values.hosts.portal | default (include "child-sso.baseHost" .) -}}
{{- end -}}

{{- define "child-sso.host.ssoBridge" -}}
{{- .Values.hosts.ssoBridge | default (printf "sso-bridge.%s" (include "child-sso.baseHost" .)) -}}
{{- end -}}

{{/* The OIDC issuer — https URL, byte-identical across all three consumers. */}}
{{- define "child-sso.issuer" -}}
{{- .Values.issuer | default (printf "https://%s/realms/%s" (include "child-sso.host.keycloak" .) .Values.realm) -}}
{{- end -}}

{{- define "child-sso.discoveryURL" -}}
{{- printf "%s/.well-known/openid-configuration" (include "child-sso.issuer" .) -}}
{{- end -}}

{{/*
-------- lookup-preserve generated secret pair --------
Computed ONCE per render and cached on .Values._gen so every consumer (the
keystone KeycloakClient CR AND the Openstack vhost) sees byte-identical values.
On re-render the existing Secrets are re-emitted (lookup) so nothing rotates.
*/}}
{{- define "child-sso.computeSecrets" -}}
{{- if not (hasKey .Values "_gen") -}}
{{-   $ns := include "child-sso.namespace" . -}}
{{-   $exClient := (lookup "v1" "Secret" $ns "keystone-oidc-client") -}}
{{-   $exCrypto := (lookup "v1" "Secret" $ns "keystone-oidc-crypto") -}}
{{-   $ks := "" -}}
{{-   $cp := "" -}}
{{-   if and $exClient $exClient.data (hasKey $exClient.data "KEYSTONE_CLIENT_SECRET") -}}
{{-     $ks = index $exClient.data "KEYSTONE_CLIENT_SECRET" | b64dec -}}
{{-   else -}}
{{-     $ks = randAlphaNum 40 -}}
{{-   end -}}
{{-   if and $exCrypto $exCrypto.data (hasKey $exCrypto.data "OIDC_CRYPTO_PASSPHRASE") -}}
{{-     $cp = index $exCrypto.data "OIDC_CRYPTO_PASSPHRASE" | b64dec -}}
{{-   else -}}
{{-     $cp = randAlphaNum 40 -}}
{{-   end -}}
{{-   $_ := set .Values "_gen" (dict "ks" $ks "cp" $cp) -}}
{{- end -}}
{{- end -}}

{{- define "child-sso.keystoneClientSecret" -}}
{{- include "child-sso.computeSecrets" . -}}{{- .Values._gen.ks -}}
{{- end -}}

{{- define "child-sso.oidcCryptoPassphrase" -}}
{{- include "child-sso.computeSecrets" . -}}{{- .Values._gen.cp -}}
{{- end -}}

{{/*
-------- MFA demo-user credentials (lookup-preserve) --------
The step-up demo user's password + TOTP secret. Computed ONCE and cached on
.Values._mfa; re-emitted from the live Secret on re-render so the MFA bootstrap Job
resets the SAME password/OTP every run (idempotent, never rotates).
*/}}
{{- define "child-sso.computeMfaSecrets" -}}
{{- if not (hasKey .Values "_mfa") -}}
{{-   $ns := include "child-sso.namespace" . -}}
{{-   $ex := (lookup "v1" "Secret" $ns "mfa-demo-cred") -}}
{{-   $pw := "" -}}
{{-   $totp := "" -}}
{{-   if and $ex $ex.data (hasKey $ex.data "KC_PASS") -}}
{{-     $pw = index $ex.data "KC_PASS" | b64dec -}}
{{-   else -}}
{{-     $pw = randAlphaNum 24 -}}
{{-   end -}}
{{-   if and $ex $ex.data (hasKey $ex.data "TOTP_SECRET") -}}
{{-     $totp = index $ex.data "TOTP_SECRET" | b64dec -}}
{{-   else -}}
{{-     $totp = randAlphaNum 32 -}}
{{-   end -}}
{{-   $_ := set .Values "_mfa" (dict "pw" $pw "totp" $totp) -}}
{{- end -}}
{{- end -}}

{{- define "child-sso.mfaPassword" -}}
{{- include "child-sso.computeMfaSecrets" . -}}{{- .Values._mfa.pw -}}
{{- end -}}

{{- define "child-sso.mfaTotpSecret" -}}
{{- include "child-sso.computeMfaSecrets" . -}}{{- .Values._mfa.totp -}}
{{- end -}}

{{/*
-------- generic init-container wait-loop --------
Usage: {{ include "child-sso.waitloop" (dict "cmd" "<test cmd>" "msg" "<desc>" "root" .) }}
Renders a container spec entry (image + shell that polls until `cmd` succeeds).
*/}}
{{- define "child-sso.waitloop" -}}
- name: wait
  image: {{ .root.Values.images.tools | quote }}
  imagePullPolicy: {{ .root.Values.images.toolsPullPolicy }}
  command:
    - /bin/sh
    - -c
    - |
      set -eu
      deadline=$(( $(date +%s) + {{ .root.Values.waitTimeoutSeconds }} ))
      echo "[wait] gate: {{ .msg }}"
      until {{ .cmd }}; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
          echo "[wait] TIMEOUT waiting for: {{ .msg }}" >&2
          exit 1
        fi
        echo "[wait] not ready ({{ .msg }}); retrying in 5s"
        sleep 5
      done
      echo "[wait] ready: {{ .msg }}"
{{- end -}}
