// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"fmt"
	"os/user"
	"strings"

	"golang.org/x/sys/windows"
)

// SystemAccounts resolves names on Windows, where a peer is only ever scrim's
// own account or another one (see [SelfUID]). A user name resolves when it
// names the account scrim runs as; any other account, and every group, is
// refused, because it could not be told apart from the rest.
type SystemAccounts struct{}

// UserID resolves name to [SelfUID] when it is scrim's own account.
func (SystemAccounts) UserID(name string) (uint32, error) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return 0, err
	}
	ours, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, err
	}
	if !sid.Equals(ours.User.Sid) {
		return 0, fmt.Errorf("on Windows identity.peers can name only the account scrim runs as; run each agent with `scrim run` for a session identity instead")
	}
	return SelfUID, nil
}

// GroupID refuses: groups cannot identify a peer on Windows.
func (SystemAccounts) GroupID(string) (uint32, error) {
	return 0, errors.New("identity.peers groups are not supported on Windows")
}

// selfName is the account name without its domain, lower-cased, so a
// typical Windows user name makes a valid agent name.
func selfName() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}
