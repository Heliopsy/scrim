// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Account is a user or group from the local account files.
type Account struct {
	Name string
	UID  int // the user or group ID
	GID  int // a user's primary group
	// Members are a group's supplementary members.
	Members []string
}

// lookup reads name from an /etc/passwd or /etc/group style file. Only the
// local files are read: an account that exists only in LDAP or another NSS
// source is not seen, and useradd or groupadd then reports the conflict.
func lookup(path, name string, group bool) (Account, bool, error) {
	f, err := os.Open(path) // #nosec G304 -- account database under the install root
	if errors.Is(err, fs.ErrNotExist) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		a := Account{Name: name}
		a.UID, _ = strconv.Atoi(fields[2])
		if group {
			if fields[3] != "" {
				a.Members = strings.Split(fields[3], ",")
			}
		} else {
			a.GID, _ = strconv.Atoi(fields[3])
		}
		return a, true, nil
	}
	return Account{}, false, sc.Err()
}

func (in *Installer) user(name string) (Account, bool, error) {
	return lookup(in.path("/etc/passwd"), name, false)
}

func (in *Installer) group(name string) (Account, bool, error) {
	return lookup(in.path("/etc/group"), name, true)
}

func (in *Installer) member(user, group string) (bool, error) {
	g, ok, err := in.group(group)
	if err != nil || !ok {
		return false, err
	}
	return slices.Contains(g.Members, user), nil
}
