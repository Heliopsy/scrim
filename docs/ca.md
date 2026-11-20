# Interception CA

The tool proxy terminates TLS toward the hosts a credential is bound to, so it can inject the
credential at the network edge. It signs a certificate for each host with scrim's own certificate
authority. Clients have to trust that CA; its private key never leaves the control plane except
in the snapshot pushed to scrim's own data plane.

`scrim ca` works without a running daemon. Every subcommand generates the CA on first use, as the
daemon would, so `scrim ca export` before the first start gives the certificate the daemon will
use.

## Where the CA lives

By default scrim generates a P-256 CA and keeps it in `$XDG_STATE_HOME/scrim/ca`
(`~/.local/state/scrim/ca` when `XDG_STATE_HOME` is unset), or in `tool-proxy.ca.dir`:

```text
ca/                       0700
  state.json              0600  current and previous generation, end of the overlap
  gen/<id>/cert.pem       0644  CA certificate
  gen/<id>/key.pem        0600  PKCS#8 private key
  trust-manifest.json     0600  changes made by `scrim ca install`
```

scrim refuses to start if the directory is reachable by group or others, if a key file is readable
by group or others, or if either belongs to another user. Errors name the file, never its content.
A rotation writes the new generation first and replaces `state.json` last, so a crash leaves
the old state or the new one, never a mix.

On a single-user machine, an agent running as the same user can read this directory. To keep the
key out of the agent's reach, run the agent as a different user, or run scrim as its own user
with the CA directory owned by it.

### Bringing your own CA

Set both:

```yaml
tool-proxy:
  ca:
    cert-file: /etc/scrim/ca.crt
    key: file:/etc/scrim/ca.key   # or env:, cred:, a store reference; a literal is refused
```

The key must be PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`; convert with
`openssl pkcs8 -topk8 -nocrypt`) and must match the certificate, which must be a CA allowed to
sign certificates. scrim never rotates an operator-supplied CA. It logs a warning once a day when
less than `tool-proxy.ca.rotate-before` of the validity remains, and refuses to start once the
CA has expired. Replace both files and restart to change it.

## Rotation

| Setting | Default | Meaning |
| --- | --- | --- |
| `tool-proxy.ca.validity` | `17520h` (2 years) | validity of each generated CA |
| `tool-proxy.ca.rotate-before` | `720h` (30 days) | rotate when this much validity remains |
| `tool-proxy.ca.overlap` | `168h` (7 days) | how long the previous CA stays trusted |

The daemon rotates on its own when the current CA is due. `scrim ca rotate` rotates now; a
running daemon picks the change up from the directory.

After a rotation the new CA signs every leaf. Until the overlap ends, each leaf is served with a
cross certificate (the new CA's name and key, signed by the previous CA), so a client that still
trusts only the previous CA keeps connecting. The previous generation and the end of its overlap
are stored in `state.json`, so a restart during the overlap changes nothing. When the overlap ends
the previous generation is deleted and leaves are served without the cross certificate.

Clients need to trust the new CA before the overlap ends. Bundle files written by
`scrim ca install --user` are refreshed at each rotation. The keychain and NSS entries are not:
run `scrim ca install --user` again after a rotation (it adds the new CA and removes entries of
generations that are no longer used).

Each generated CA has a distinct subject (`scrim interception CA <unix time> <serial prefix>`,
organisation `scrim`), path length 1 so the cross certificate is accepted below it, and key
usages keyCertSign, cRLSign and digitalSignature.

## Export

```sh
scrim ca export                 # PEM to stdout: current CA, then the previous one during an overlap
scrim ca export --out ca.pem
```

Only public certificates are printed. Use the export for container images, CI runners or a
system trust store.

## Install and uninstall

```sh
scrim ca install --user --dry-run   # show what would change
scrim ca install --user
scrim ca uninstall --user
```

`install` prints every change before making it and records each one in `trust-manifest.json`.
`uninstall` reverts exactly what the manifest lists, newest first. A change it cannot revert stays
in the manifest and is printed with the manual step, and the command exits 1.

| OS | Store | Change | Revert |
| --- | --- | --- | --- |
| macOS | login keychain | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db` (macOS asks for confirmation) | `security remove-trusted-cert`, `security delete-certificate -Z <sha1>` |
| Linux | `~/.pki/nssdb` (Chromium, Chrome, Edge), when it exists and `certutil` is installed | `certutil -d sql:~/.pki/nssdb -A -t C,, -n <name>` | `certutil -D -n <name>` |
| all | `$XDG_DATA_HOME/scrim/scrim-ca.pem` (`~/.local/share/scrim`) | the scrim CA certificates | file removed |
| all | `$XDG_DATA_HOME/scrim/ca-bundle.pem` | the system roots (first found of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`, `/etc/ssl/cert.pem`) plus the scrim CA | file removed |

Runtimes with their own trust read environment variables. `install` prints them; set them in the
agent's environment:

```sh
export NODE_EXTRA_CA_CERTS=~/.local/share/scrim/scrim-ca.pem   # adds to Node's roots
export SSL_CERT_FILE=~/.local/share/scrim/ca-bundle.pem        # OpenSSL, Go, Ruby; replaces the roots
export REQUESTS_CA_BUNDLE=~/.local/share/scrim/ca-bundle.pem   # Python requests
export CURL_CA_BUNDLE=~/.local/share/scrim/ca-bundle.pem
export GIT_SSL_CAINFO=~/.local/share/scrim/ca-bundle.pem
```

The variables that replace the roots point at the combined bundle, so other HTTPS keeps working.
When no system bundle is found, the combined bundle is not written and only
`NODE_EXTRA_CA_CERTS` is printed.

## Not covered yet

- `scrim ca install --system`. The system trust store is set up by `scrim install --system`
  (`update-ca-certificates` on Debian and Ubuntu, `update-ca-trust` on Fedora and RHEL), recorded
  in the install manifest and reverted by `scrim uninstall` ([service.md](service.md)). macOS
  (`security add-trusted-cert -d`) is not automated.
- Firefox profiles (each has its own NSS database), Java keystores (`keytool`), and creating
  `~/.pki/nssdb` when it does not exist.
- Writing the environment variables into shell profiles or agent settings. `scrim install --user`
  runs `scrim ca install --user` and prints them; `scrim run` sets them for the agent it starts.
- Reloading `tool-proxy.ca.*` settings without a restart.
