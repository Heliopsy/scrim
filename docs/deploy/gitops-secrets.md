# Secrets in GitOps

No secret value goes into Git in plain text, and most of scrim's secrets need not go into
Kubernetes at all. Sort them first:

| Credential | What it is | Where it lives |
| --- | --- | --- |
| Agent secrets (GitHub token, npm token, database password) | the values scrim redacts and injects | in your secret store. scrim reads them with its own identity through a store reference (`bao://kv/agents/github#token`); they never become Kubernetes Secrets and never pass through Flux, Argo CD or External Secrets |
| scrim's store login | how scrim authenticates to OpenBao, Infisical or Vaultwarden | a Kubernetes Secret mounted into scrim (`secretMounts`, a `file:` reference), or nothing at all with Kubernetes auth from scrim's service account once that ships |
| `scrim-keys` | placeholder key, approvals signing key | a Kubernetes Secret, generated once, shared by every replica |
| `scrim-ca` | the interception CA (`tls.crt`, PKCS#8 `tls.key`) | a Kubernetes Secret; the certificate is public, the key is not |
| `scrim-postgres` | the PostgreSQL DSN with its password | a Kubernetes Secret |

So a GitOps setup carries three or four Secrets for scrim itself, whatever the number of agent
secrets. Agents never read a value back through scrim either: they get references and placeholders.

When a store cannot be reached from the cluster, or for a small setup, agent secrets can still
come from a Kubernetes Secret through the file store (`files://agents/<key>`, as the raw manifests
and the kustomize base do). Then they are one more Secret below.

Files: [`deploy/examples/secrets/`](../../deploy/examples/secrets/).

## SOPS with age

For Flux, which decrypts SOPS natively. The private age key lives only in the cluster and with the
people who edit secrets.

```sh
age-keygen -o scrim.agekey                      # keep it out of git
age-keygen -y scrim.agekey                      # the public key, for .sops.yaml
kubectl --context "$CONTEXT" -n flux-system create secret generic sops-age \
  --from-file=age.agekey=scrim.agekey
```

[`.sops.yaml`](../../deploy/examples/secrets/sops/.sops.yaml) encrypts only `data` and
`stringData`, so names and labels stay readable in review. Put your public key in it, write the
Secret, encrypt it in place:

```sh
cd secrets/prod                                  # in your fleet repository
cat > scrim-keys.sops.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: scrim-keys
  namespace: scrim
stringData:
  placeholder-k1: $(openssl rand -hex 32)
  approvals-signing-key: $(openssl rand -hex 32)
EOF
sops --encrypt --in-place scrim-keys.sops.yaml
git add scrim-keys.sops.yaml
```

The committed [`scrim-keys.sops.yaml`](../../deploy/examples/secrets/sops/scrim-keys.sops.yaml) and
[`scrim-postgres.sops.yaml`](../../deploy/examples/secrets/sops/scrim-postgres.sops.yaml) show the
result; their key was thrown away and their plain text was a placeholder. The Flux Kustomization
`scrim-secrets` decrypts them ([flux.md](flux.md)):

```yaml
decryption:
  provider: sops
  secretRef:
    name: sops-age
```

`sops edit secrets/prod/scrim-postgres.sops.yaml` changes a value; rotating the age key is
`sops updatekeys` after changing `.sops.yaml`.

## External Secrets Operator with OpenBao

For Argo CD, or when the values should stay in OpenBao. External Secrets Operator reads them with
its own Kubernetes service account and writes the Kubernetes Secrets.

| File | Creates |
| --- | --- |
| [`clustersecretstore-openbao.yaml`](../../deploy/examples/secrets/external-secrets/clustersecretstore-openbao.yaml) | the ClusterSecretStore `openbao` (vault provider, KV v2, Kubernetes auth role `external-secrets-scrim`) |
| [`scrim-keys.yaml`](../../deploy/examples/secrets/external-secrets/scrim-keys.yaml) | `scrim-keys` from `secret/scrim/keys` |
| [`scrim-ca.yaml`](../../deploy/examples/secrets/external-secrets/scrim-ca.yaml) | `scrim-ca`, type `kubernetes.io/tls`, from `secret/scrim/ca` |
| [`scrim-postgres.yaml`](../../deploy/examples/secrets/external-secrets/scrim-postgres.yaml) | `scrim-postgres` from `secret/scrim/postgres` |

Put the values into OpenBao once:

```sh
bao kv put secret/scrim/keys placeholder-k1="$(openssl rand -hex 32)" \
  approvals-signing-key="$(openssl rand -hex 32)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls.key -out tls.crt \
  -days 730 -subj "/O=scrim/CN=scrim interception CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
bao kv put secret/scrim/ca tls.crt=@tls.crt tls.key=@tls.key && rm tls.key
bao kv put secret/scrim/postgres dsn=-     # paste the DSN, then Ctrl-D
```

The OpenBao role for External Secrets needs read on `secret/data/scrim/*` and nothing else. scrim's
own OpenBao identity is a different role with read on the agents' tree
([OpenBao least privilege](../stores/openbao.md#least-privilege)); neither can read what the other
reads.

## scrim's own store references

Inside scrim's configuration, credentials are references, never literals, whether the file comes
from Helm values, a ConfigMap or a workstation:

```yaml
stores:
  bao:
    kind: openbao
    address: https://bao.example.com:8200
    token: file:/run/secrets/scrim/bao/token       # a mounted Secret
    redact: ["bao://kv/agents/*"]
state:
  postgres:
    dsn: file:/run/secrets/scrim-postgres/dsn
```

`env:NAME`, `file:/path`, `cred:NAME` (systemd credentials) and store references are accepted;
the Helm chart refuses a literal in a store's credential fields, and `scrim config validate`
resolves every `env:`, `file:` and `cred:` reference without contacting a store
([configuration.md](../configuration.md#secret-valued-settings)).

## Check that nothing leaked into Git

```sh
gitleaks git --redact --no-banner .            # the repository's history
grep -rL 'ENC\[' secrets/*/*.sops.yaml         # prints any SOPS file that is not encrypted
```

`just deploy-examples-check` fails when a committed `*.sops.yaml` example has a value that is not
encrypted.
