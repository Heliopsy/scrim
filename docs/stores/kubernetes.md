# Kubernetes Secrets

The `kubernetes` adapter reads Secrets from a Kubernetes cluster: from the namespace scrim runs in,
with its pod's service account, or from any cluster named by a kubeconfig file and context. Each
data key of a Secret is a field. The source is read-only unless you set `writable: true`.

## References

An instance either covers a list of namespaces, and references start with the namespace, or is
confined to one namespace, and references are the Secret name alone:

| Option | Reference | Secret |
| --- | --- | --- |
| `namespaces: [prod, agents]` | `k8s://prod/db-credentials#password` | `db-credentials` in `prod`, key `password` |
| `namespace: prod` | `k8s://db-credentials#password` | the same |

A Secret name is DNS labels joined by dots. A reference writes each dot as a slash, so
`tls.example.com` in `prod` is `k8s://prod/tls/example/com` and `k8s://prod/tls/*` covers every
Secret whose name starts with `tls.`. The mapping is one to one: a reference, a listed path and a
watched path always agree. A segment that is not a lower-case DNS label (a dot, an underscore, an
upper-case letter) is an invalid reference.

Listing and redact targets:

- `k8s://prod/*` (or `k8s://*` for every configured namespace) loads every Secret there.
- `k8s://prod/app/*` loads `app` and every Secret named `app.<something>`.
- `k8s://prod/app-*` is a glob: every Secret whose name starts with `app-`. A glob must follow part
  of a name, not a namespace.
- A namespace outside the configured ones is refused with a permission error, never looked up.

Version selectors (`?version=`) are refused: Kubernetes keeps no history of a Secret.

## Capabilities

| Kind | read | list | watch | write | generate | dynamic | glob |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `kubernetes` | yes | yes | yes | with `writable: true` | no | no | yes |

Without `writable: true` the adapter does not declare write, and a write or generate is refused
before any API call: `store k8s: write k8s://prod/new: operation not supported by this store:
kubernetes source is read-only; set writable: true to allow writes`.

## Configuration

In a pod, with the pod's service account:

```yaml
stores:
  k8s:
    kind: kubernetes
    namespace: agents
    redact:
      - k8s://*
```

From anywhere, with one context of one kubeconfig file:

```yaml
stores:
  k8s-prod:
    kind: kubernetes
    auth:
      method: kubeconfig
      kubeconfig: /etc/scrim/kubeconfig-prod
      context: prod-admin
    namespaces: [payments, agents]
    writable: true
    redact:
      - k8s-prod://payments/*
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stores.<name>.kind` | string | | `kubernetes` |
| `stores.<name>.auth.method` | string | `in-cluster` | `in-cluster` (the pod's service account) or `kubeconfig`. |
| `stores.<name>.auth.kubeconfig` | string | | Absolute path of the kubeconfig file. Required with `kubeconfig`, refused otherwise. |
| `stores.<name>.auth.context` | string | | Context in that file. Required with `kubeconfig`, refused otherwise. |
| `stores.<name>.namespace` | string | | The one namespace of the instance; references carry no namespace. |
| `stores.<name>.namespaces` | list of strings | | The namespaces the instance may use; references start with one. As an environment variable, separate entries with commas. |
| `stores.<name>.writable` | bool | `false` | Allow writes (create and update, never delete). |
| `stores.<name>.timeout` | duration | `10s` | Deadline of every API request except watches. |

Set exactly one of `namespace` and `namespaces`: scrim never reads a whole cluster.

scrim never picks a cluster for you. It does not read `KUBECONFIG`, does not fall back to
`~/.kube/config`, and ignores a kubeconfig's `current-context`: with `auth.method: kubeconfig` the
file and the context are both required, so a shell that last pointed at another cluster cannot move
scrim with it. A kubeconfig that uses an exec credential plugin runs that plugin as usual.

## Least privilege

scrim needs `get`, `list` and `watch` on Secrets in each configured namespace, plus `create` and
`update` when the instance is writable. It never deletes. Bind a Role per namespace rather than a
ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: scrim-secrets
  namespace: agents
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list, watch]
    # Add create and update for writable: true.
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: scrim-secrets
  namespace: agents
subjects:
  - kind: ServiceAccount
    name: scrim
    namespace: scrim
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: scrim-secrets
```

`resourceNames` cannot limit `list` and `watch`, so a Role that names Secrets only works for an
instance that reads named references and never lists or watches; use a namespace of its own for the
Secrets scrim may see instead.

## Labels

| Key | Meaning |
| --- | --- |
| `kubernetes.namespace` | Namespace of the Secret. |
| `kubernetes.name` | Secret name, with its dots. |
| `kubernetes.type` | Secret type: `Opaque`, `kubernetes.io/tls`, `kubernetes.io/dockerconfigjson`, ... |
| `kubernetes.meta.label.<key>` | Each label of the Secret, key folded (`app.kubernetes.io/name` becomes `kubernetes.meta.label.app.kubernetes.io_name`). |
| `kubernetes.meta.annotation.<key>` | Each annotation, folded the same way. |
| `scrim.*` | Annotations whose key starts with `scrim.` (`scrim.hosts`), under their own key. |

The prefix is the adapter kind, `kubernetes.`, like every adapter's; name the instance `k8s` if you
want short references. The native keys come from what the API server fixes for an object: its
address and its type, which cannot change after creation. Labels and annotations are editable by
anyone who may update the Secret, so they stay under `kubernetes.meta.` and never replace a native
key: a label `kubernetes.namespace: prod` on a Secret in `dev` shows up as
`kubernetes.meta.label.kubernetes.namespace` and `kubernetes.namespace` stays `dev`. The
`kubectl.kubernetes.io/last-applied-configuration` annotation holds the whole object as last
applied, data included, and is never read into a label.

Example rules. `kubernetes.namespace`, `kubernetes.name` and `kubernetes.type` are always present on
a Secret read from the cluster; guard the `meta` keys with `in`:

```yaml
rules:
  # Never hand out service account tokens, whichever namespace they are in.
  - name: no-sa-tokens
    decision: deny
    when: >-
      "kubernetes.type" in secret.labels &&
      secret.labels["kubernetes.type"] == "kubernetes.io/service-account-token"

  # Secrets in payments, or labelled team=payments, need approval.
  - name: payments-asks
    decision: ask
    when: >-
      ("kubernetes.namespace" in secret.labels &&
       secret.labels["kubernetes.namespace"] == "payments") ||
      ("kubernetes.meta.label.team" in secret.labels &&
       secret.labels["kubernetes.meta.label.team"] == "payments")
```

Before a Secret exists, a `store.write` or `secret.gen` rule sees `kubernetes.namespace` and
`kubernetes.name` from the reference. A lookup of an existing Secret's labels (a write to it) uses
the server-side table form of the API, which returns the metadata and type without the data.

## Watch

Watch uses the API server's own watch, in its metadata-only form: change events carry names and
resource versions, never data. scrim lists each namespace once to get a starting version, watches
from there, and resumes from the last version it saw when the server closes a watch. If the version
has expired (`410 Gone`) or the API server was unreachable, it lists the namespace again and reports
what was created, changed or deleted in between. Retries back off up to 10 seconds. List and the
label lookup use metadata-only requests too; only reading a Secret and writing one move values.

## Writes

With `writable: true`, a write creates an `Opaque` Secret, or replaces the data of an existing one:
the written fields become the Secret's whole data, and its type, labels and annotations stay. A
create-only write (`secret_capture` without overwrite) fails with a conflict when the Secret exists.
An update that races another writer is retried from a fresh read.

Write labels (`scrim.hosts`, ...) are stored as annotations of the same name and read back as
labels. A label outside `scrim.*`, or a key Kubernetes does not accept as an annotation, is refused
before the write, since it could not be read back as written. A data key may hold letters, digits,
`-`, `_` and `.`.

## Values in memory

Values reach scrim through client-go as byte slices, which scrim adopts into its secret type without
another copy and wipes when they leave the redaction set. Two buffers are outside its reach: the
HTTP response a Secret was decoded from (scrim asks for protobuf, so values never pass through base64
text, but client-go owns that buffer) and, on writes, the encoded request body. Both are released to
the Go garbage collector, not wiped.

## Errors

| API server answer | Error kind |
| --- | --- |
| 404 | not found |
| 401, 403 | permission denied by store |
| 409 (exists, conflict) | conflict |
| 400, 413, 422 (invalid) | operation not supported by this store |
| anything else, timeouts, connection failures | store unavailable |

Errors carry the HTTP code and reason, never the API server's message: an admission webhook can
quote request data in it.

## Testing

The adapter's tests run the conformance suite against a real API server, read-only (confined to one
namespace, seeded out of band) and writable (two namespaces, writes elsewhere refused), through a
local proxy that can cut the connection to test outages. They skip unless
`SCRIM_TEST_KUBECONFIG` (an absolute path) and `SCRIM_TEST_KUBE_CONTEXT` are set;
`SCRIM_TEST_KUBERNETES=1` turns a missing cluster into a failure. With a throwaway kind cluster on
rootless podman:

<!-- docs-test: skip: creates a kind cluster -->
```sh
export KIND_EXPERIMENTAL_PROVIDER=podman
kind create cluster --name scrim-k8s-test --kubeconfig "$PWD/kind.kubeconfig"
SCRIM_TEST_KUBECONFIG="$PWD/kind.kubeconfig" SCRIM_TEST_KUBE_CONTEXT=kind-scrim-k8s-test \
  go test -race ./internal/stores/kubernetes/
kind delete cluster --name scrim-k8s-test --kubeconfig "$PWD/kind.kubeconfig"
```
