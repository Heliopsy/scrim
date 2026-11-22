// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package keyring

import (
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

func TestParsePasswordLine(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"keychain: \"/x\"\npassword: \"s3cret with spaces \"\n", "s3cret with spaces ", true},
		{"password: \"quote\"inside\"\n", `quote"inside`, true},
		{"password: 0x6C696E650A74776F  \"line\\012two\"\n", "line\ntwo", true},
		{"password: 0xC3A9\n", "é", true},
		{"password: \n", "", true},
		{"password:\n", "", true},
		{"password: 0xZZ\n", "", false},
		{"password: unquoted\n", "", false},
		{"nothing here\n", "", false},
	}
	for _, c := range cases {
		got, err := parsePasswordLine([]byte(c.in))
		if (err == nil) != c.ok || (c.ok && string(got) != c.want) {
			t.Errorf("parsePasswordLine(%q) = %q, %v; want %q ok=%v", c.in, got, err, c.want, c.ok)
		}
		if err != nil && strings.Contains(err.Error(), "unquoted") {
			t.Errorf("parse error echoes the password: %v", err)
		}
	}
	out := []byte("    \"acct\"<blob>=\"me\"\n    \"labl\"<blob>=\"Deploy key\"\n")
	if got := keychainAttr(out, "labl"); got != "Deploy key" {
		t.Errorf("keychainAttr = %q", got)
	}
}

func TestKeychainErrors(t *testing.T) {
	ctx := t.Context()
	// A real *exec.ExitError from a command that fails.
	k := &keychain{tool: "/bin/sh"}
	_, _, exitErr := k.run(ctx, "-c", "exit 44")
	if exitErr == nil {
		t.Skip("no /bin/sh")
	}
	cases := map[string]error{
		"security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.": stores.ErrNotFound,
		"security: SecKeychainItemCopyAttributesAndData: User interaction is not allowed.":            stores.ErrLocked,
		"security: The specified keychain could not be found.":                                        stores.ErrUnavailable,
		"something else": stores.ErrUnavailable,
	}
	for msg, want := range cases {
		if err := keychainError(ctx, []byte(msg), exitErr); !errors.Is(err, want) {
			t.Errorf("%q -> %v, want %v", msg, err, want)
		}
	}
}
