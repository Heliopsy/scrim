// SPDX-License-Identifier: AGPL-3.0-only

package fspermtest

import (
	"golang.org/x/sys/windows"
)

func open(path string) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	// Full access for the user, read for Everyone (WD), not inherited from
	// the parent.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + tu.User.Sid.String() + ")(A;OICI;FR;;;WD)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
