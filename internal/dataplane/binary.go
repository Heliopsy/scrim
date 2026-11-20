// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

// Binary is the data plane executable to run.
type Binary struct {
	// Image is the executable's content.
	Image []byte
	// Sum is the SHA-256 of Image.
	Sum [32]byte
	// Source says where it came from: "embedded" or the file path.
	Source string
}

// ErrNoBinary means this build embeds no data plane and none was configured.
var ErrNoBinary = errors.New("this build has no embedded data plane; set dataplane.path or build with `just build`")

// Resolve returns the configured binary: the file at path when set,
// otherwise the embedded one.
func Resolve(path string) (Binary, error) {
	if path != "" {
		img, err := os.ReadFile(path)
		if err != nil {
			return Binary{}, fmt.Errorf("dataplane.path: %w", err)
		}
		return Binary{Image: img, Sum: sha256.Sum256(img), Source: path}, nil
	}
	if len(embedded) == 0 {
		return Binary{}, ErrNoBinary
	}
	return Binary{Image: embedded, Sum: sha256.Sum256(embedded), Source: "embedded"}, nil
}

// Embedded reports whether this build carries the data plane.
func Embedded() bool { return len(embedded) > 0 }
