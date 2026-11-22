// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package keyring

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// keychain is the macOS backend: generic passwords read with
// /usr/bin/security, which needs no cgo. The value is read from the
// `password:` line `-g` writes to stderr, which is unambiguous (quoted text,
// or 0x-prefixed hex for anything not printable), unlike `-w`, whose hex
// output cannot be told apart from a password that is itself hex. Nothing
// is passed on the command line but the service, the account and the
// keychain path.
type keychain struct {
	cfg  Config
	tool string
}

func newKeychain(cfg Config) *keychain { return &keychain{cfg: cfg, tool: "/usr/bin/security"} }

func (k *keychain) caps() stores.Capabilities { return stores.CapRead }

func (k *keychain) args(service, account string, withPassword bool) []string {
	a := []string{"find-generic-password", "-s", service, "-a", account}
	if withPassword {
		a = append(a, "-g")
	}
	if k.cfg.Keychain != "" {
		a = append(a, k.cfg.Keychain)
	}
	return a
}

// run runs the tool and returns stdout and stderr; the caller wipes both.
func (k *keychain) run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, k.tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.Bytes(), e.Bytes(), err
}

func (k *keychain) read(ctx context.Context, service, account string) (item, secret.Value, error) {
	stdout, stderr, err := k.run(ctx, k.args(service, account, true)...)
	defer secret.WipeBytes(stdout)
	defer secret.WipeBytes(stderr)
	if err != nil {
		return item{}, secret.Value{}, keychainError(ctx, stderr, err)
	}
	v, err := parsePasswordLine(stderr)
	if err != nil {
		return item{}, secret.Value{}, kerr(stores.ErrUnavailable, "unexpected output from security: "+err.Error(), nil)
	}
	it := item{service: service, account: account, label: keychainAttr(stdout, "labl")}
	return it, secret.Adopt(v), nil
}

func (k *keychain) meta(ctx context.Context, service, account string) (item, error) {
	stdout, stderr, err := k.run(ctx, k.args(service, account, false)...)
	defer secret.WipeBytes(stdout)
	if err != nil {
		return item{}, keychainError(ctx, stderr, err)
	}
	return item{service: service, account: account, label: keychainAttr(stdout, "labl")}, nil
}

func (k *keychain) list(context.Context, string) ([]item, error) {
	return nil, kerr(stores.ErrUnsupported, "the keychain backend cannot list", nil)
}

func (k *keychain) health(ctx context.Context) error {
	args := []string{"show-keychain-info"}
	if k.cfg.Keychain != "" {
		args = append(args, k.cfg.Keychain)
	}
	_, stderr, err := k.run(ctx, args...)
	if err != nil {
		return keychainError(ctx, stderr, err)
	}
	return nil
}

func (k *keychain) close() error { return nil }

// keychainError maps a failed security run. stderr of a failed run holds
// no password; only fixed phrases are matched and nothing of it is
// returned.
func keychainError(ctx context.Context, stderr []byte, err error) error {
	if ctx.Err() != nil {
		return kerr(stores.ErrUnavailable, "security did not answer in time", ctx.Err())
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return kerr(stores.ErrUnavailable, "cannot run /usr/bin/security", err)
	}
	msg := string(stderr)
	switch {
	case strings.Contains(msg, "keychain could not be found"), strings.Contains(msg, "No such keychain"):
		return kerr(stores.ErrUnavailable, "keychain not found", nil)
	case strings.Contains(msg, "could not be found"):
		return kerr(stores.ErrNotFound, "", nil)
	case strings.Contains(msg, "User interaction is not allowed"), strings.Contains(msg, "locked"):
		return kerr(stores.ErrLocked, "keychain is locked or the item needs approval; unlock it and allow /usr/bin/security (scrim never prompts)", nil)
	case strings.Contains(msg, "denied"), strings.Contains(msg, "not permitted"):
		return kerr(stores.ErrPermission, "access to the item was denied", nil)
	}
	return kerr(stores.ErrUnavailable, "security failed with exit status "+strconv.Itoa(ee.ExitCode()), nil)
}

// parsePasswordLine extracts the value from the `password:` line that
// `security find-generic-password -g` writes to stderr:
//
//	password: "text"
//	password: 0x6C696E650A  "line\012"
//	password:
//
// The result is a fresh slice the caller owns.
func parsePasswordLine(stderr []byte) ([]byte, error) {
	const prefix = "password:"
	for line := range bytes.Lines(stderr) {
		line = bytes.TrimRight(line, "\r\n")
		rest, ok := bytes.CutPrefix(line, []byte(prefix))
		if !ok {
			continue
		}
		switch {
		case len(rest) == 0 || (len(rest) == 1 && rest[0] == ' '):
			return []byte{}, nil
		case bytes.HasPrefix(rest, []byte(" 0x")):
			h := rest[3:]
			if i := bytes.IndexByte(h, ' '); i >= 0 {
				h = h[:i]
			}
			out := make([]byte, hex.DecodedLen(len(h)))
			if _, err := hex.Decode(out, h); err != nil {
				secret.WipeBytes(out)
				return nil, errors.New("malformed hex password")
			}
			return out, nil
		case len(rest) >= 3 && rest[0] == ' ' && rest[1] == '"' && rest[len(rest)-1] == '"':
			return bytes.Clone(rest[2 : len(rest)-1]), nil
		}
		return nil, errors.New("unrecognised password line")
	}
	return nil, errors.New("no password line")
}

// keychainAttr returns a quoted string attribute (`"labl"<blob>="x"`) from
// the attribute listing security writes to stdout, or "".
func keychainAttr(stdout []byte, name string) string {
	keys := [][]byte{[]byte(`"` + name + `"<blob>="`)}
	// security prints a few attributes by number: the label is 7.
	if name == "labl" {
		keys = append(keys, []byte(`0x00000007 <blob>="`))
	}
	for line := range bytes.Lines(stdout) {
		line = bytes.TrimSpace(line)
		for _, key := range keys {
			if rest, ok := bytes.CutPrefix(line, key); ok && bytes.HasSuffix(rest, []byte(`"`)) {
				return string(rest[:len(rest)-1])
			}
		}
	}
	return ""
}
