// SPDX-License-Identifier: AGPL-3.0-only

package sshkeys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
)

func x509MarshalEC(k *ecdsa.PrivateKey) ([]byte, error) { return x509.MarshalECPrivateKey(k) }
func x509MarshalPKCS1(k *rsa.PrivateKey) []byte         { return x509.MarshalPKCS1PrivateKey(k) }
