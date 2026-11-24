// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package identity

import (
	"os"
	"os/user"
	"strconv"
)

// SystemAccounts resolves names through os/user.
type SystemAccounts struct{}

// UserID looks up a user name.
func (SystemAccounts) UserID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return parseID(u.Uid)
}

// GroupID looks up a group name.
func (SystemAccounts) GroupID(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return parseID(g.Gid)
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// selfName is the name of the user scrim runs as, or "".
func selfName() string {
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		return u.Username
	}
	return ""
}
