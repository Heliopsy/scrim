// SPDX-License-Identifier: AGPL-3.0-only

package fsperm

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trusted are the accounts that may hold access to a private file besides
// its owner: they can read every file on the machine regardless.
func trusted() ([]*windows.SID, error) {
	me, err := currentUser()
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{me, system, admins}, nil
}

func currentUser() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

func contains(sids []*windows.SID, s *windows.SID) bool {
	for _, t := range sids {
		if t.Equals(s) {
			return true
		}
	}
	return false
}

func loose0(path string, _ fs.FileInfo) (bool, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, "", err
	}
	ok, err := trusted()
	if err != nil {
		return false, "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, "", err
	}
	// The owner can always rewrite the DACL, so an owner outside the
	// trusted accounts makes the file loose whatever the DACL says.
	if owner == nil || !contains(ok, owner) {
		return true, "owned by " + name(owner), nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return true, "no DACL: every account has full access", nil
		}
		return false, "", err
	}
	if dacl == nil {
		return true, "no DACL: every account has full access", nil
	}
	others := map[string]bool{}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, "", err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to children only
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // only ever takes access away
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			// Object, callback and compound ACEs are not expected on files;
			// one that grants anything is counted as a grant to others.
			others[fmt.Sprintf("an ACE of type %d", ace.Header.AceType)] = true
			continue
		}
		// The SID starts at SidStart and runs to the end of the ACE.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // the ACE layout puts the SID at SidStart
		if contains(ok, sid) || isOwnerRights(sid) {
			continue
		}
		others[name(sid)] = true
	}
	if len(others) == 0 {
		return false, "", nil
	}
	names := make([]string, 0, len(others))
	for n := range others {
		names = append(names, n)
	}
	sort.Strings(names)
	return true, "the DACL grants " + strings.Join(names, ", "), nil
}

// isOwnerRights is OWNER RIGHTS (S-1-3-4), which grants whoever owns the
// file: the owner was checked above.
func isOwnerRights(s *windows.SID) bool { return s.String() == "S-1-3-4" }

func name(s *windows.SID) string {
	if s == nil {
		return "nobody"
	}
	if acct, dom, _, err := s.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acct
		}
		return acct
	}
	return s.String()
}

// Restrict replaces path's DACL with a protected one that grants full
// access to the current user, SYSTEM and Administrators only, inherited by
// files and directories created inside it.
func Restrict(path string) error {
	me, err := currentUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restricting the access of %s: %w", path, err)
	}
	return nil
}

// Owned returns an error unless path is owned by the current user (or by
// SYSTEM or Administrators, which own what an elevated process creates).
func Owned(path string, _ fs.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	ok, err := trusted()
	if err != nil {
		return err
	}
	if owner == nil || !contains(ok, owner) {
		return fmt.Errorf("%s is not owned by this user (owner %s)", path, name(owner))
	}
	return nil
}

// FixHint says how to make path private.
func FixHint(path string, dir bool) string {
	flags := ""
	if dir {
		flags = "(OI)(CI)"
	}
	return fmt.Sprintf("run `icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:%sF\" SYSTEM:%sF Administrators:%sF` "+
		"and remove any other account `icacls \"%s\"` still lists with /remove", path, flags, flags, flags, path)
}
