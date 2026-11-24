// SPDX-License-Identifier: AGPL-3.0-only

package fsperm

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// openUp adds an ACE granting Everyone read access, the way a directory
// under C:\ or a shared folder inherits one.
func openUp(t *testing.T, path string) {
	t.Helper()
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + me.String() + ")(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRestrictTightensALooseDirectory(t *testing.T) {
	dir := t.TempDir()
	openUp(t, dir)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	loose, detail, err := Loose(dir, fi)
	if err != nil || !loose || !strings.Contains(detail, "Everyone") {
		t.Fatalf("before Restrict: Loose = %v, %q, %v; want loose naming Everyone", loose, detail, err)
	}
	if err := Restrict(dir); err != nil {
		t.Fatal(err)
	}
	if loose, detail, err := Loose(dir, fi); err != nil || loose {
		t.Fatalf("after Restrict: Loose = %v, %q, %v; want private", loose, detail, err)
	}
}
