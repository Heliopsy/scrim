# scrim ca

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim ca

Export, rotate and install the tool proxy's interception CA.

```text
scrim ca [command]

The tool proxy signs certificates for the hosts it intercepts with scrim's own CA. Its private key stays in the CA
directory (tool-proxy.ca.dir); these commands only ever print or install the public certificates.

With --edge, export and rotate act on the edge CA instead (edge.ca.*): the separate, name-constrained CA that issues
only the edge listener's certificate, which the edge forwarders trust. It is never installed into a trust store.

Every command works without a running daemon. The CA is generated on first use, as the daemon would.
```

| Subcommand | Description |
| --- | --- |
| [`scrim ca export`](#scrim-ca-export) | Print the PEM certificates clients must trust (current CA, and the previous one during an overlap) |
| [`scrim ca install`](#scrim-ca-install) | Trust the CA in the per-user trust stores and write bundle files for runtimes with their own trust |
| [`scrim ca rotate`](#scrim-ca-rotate) | Make a new CA current; the previous one stays trusted for tool-proxy.ca.overlap |
| [`scrim ca uninstall`](#scrim-ca-uninstall) | Revert every trust change `scrim ca install --user` recorded |

## scrim ca export

Print the PEM certificates clients must trust (current CA, and the previous one during an overlap).

```text
scrim ca export [flags]
```

Flags:

```text
      --edge[=true|false]   the edge CA (edge.ca.*), for the edge forwarders' edge-forwarder.ca-file
      --out string          write the bundle to this file instead of stdout
```

## scrim ca install

Trust the CA in the per-user trust stores and write bundle files for runtimes with their own trust.

```text
scrim ca install --user [flags]

Shows each change before making it and records it in the trust manifest in the CA directory, so `scrim ca uninstall
--user` reverts exactly those changes.

macOS: the login keychain (security add-trusted-cert; macOS asks to confirm).
Linux: the NSS database ~/.pki/nssdb (Chromium-based browsers) when it exists and certutil is installed.
Everywhere: $XDG_DATA_HOME/scrim/scrim-ca.pem for NODE_EXTRA_CA_CERTS and ca-bundle.pem (system roots plus the scrim CA)
for SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE and GIT_SSL_CAINFO.

Run it again after a rotation to add the new CA; entries of generations no longer in use are removed.
```

Flags:

```text
      --dry-run[=true|false]   show the changes without making them
      --system[=true|false]    use the system trust store (done by scrim install --system)
      --user[=true|false]      use the per-user trust stores
```

## scrim ca rotate

Make a new CA current; the previous one stays trusted for tool-proxy.ca.overlap.

```text
scrim ca rotate [flags]

Generates a new CA generation and makes it current. The previous generation stays trusted through a cross certificate
until tool-proxy.ca.overlap ends. A running daemon picks the change up from the CA directory. An operator-supplied CA
(tool-proxy.ca.cert-file) is never rotated by scrim.
```

Flags:

```text
      --edge[=true|false]   rotate the edge CA (edge.ca.*) instead; a running daemon picks it up from edge.ca.dir
```

## scrim ca uninstall

Revert every trust change `scrim ca install --user` recorded.

```text
scrim ca uninstall --user [flags]

Reverts each change listed in the trust manifest. A change that cannot be reverted stays listed and is reported with the
manual step to undo it; the command then exits 1.
```

Flags:

```text
      --dry-run[=true|false]   show the changes without making them
      --system[=true|false]    use the system trust store (done by scrim install --system)
      --user[=true|false]      use the per-user trust stores
```
