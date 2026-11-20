// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"bytes"
	"os"
)

// systemBundles are the usual locations of the system trust store as one
// PEM file, by distribution.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL, CentOS
	"/etc/ssl/ca-bundle.pem",                            // openSUSE
	"/etc/ssl/cert.pem",                                 // macOS, Alpine, OpenBSD
}

// maxPEM bounds a trust file read into the session bundle.
const maxPEM = 16 << 20

// trustInputs returns the PEM the session bundle starts from and the PEM of
// an inherited NODE_EXTRA_CA_CERTS file. A bundle the user already points
// SSL_CERT_FILE at (a corporate CA, say) is kept, so the session trusts what
// the user's shell trusts plus scrim's CA.
func trustInputs(env map[string]string) (roots, nodeExtra []byte) {
	if f := env["SSL_CERT_FILE"]; f != "" {
		roots = readPEM(f)
	}
	for _, f := range systemBundles {
		if roots != nil {
			break
		}
		roots = readPEM(f)
	}
	if f := env["NODE_EXTRA_CA_CERTS"]; f != "" {
		nodeExtra = readPEM(f)
	}
	return roots, nodeExtra
}

// readPEM returns the file's content when it holds certificates and no
// private key.
func readPEM(path string) []byte {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxPEM {
		return nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- a trust store path, public certificates only
	if err != nil || !bytes.Contains(b, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Contains(b, []byte("PRIVATE KEY")) {
		return nil
	}
	return b
}
