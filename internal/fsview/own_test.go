// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package fsview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func byTarget(es []Entry) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range es {
		m[e.Target] = e
	}
	return m
}

// ownFiles writes scrim's own files of a user-level install: a config file
// and a file: reference target under the home, a state directory, and a
// key file outside the home.
func ownFiles(t *testing.T, home string) (outside string, own []OwnPath) {
	t.Helper()
	outside = t.TempDir()
	write(t, filepath.Join(home, ".config/scrim/config.yaml"), "cfg")
	write(t, filepath.Join(home, ".config/scrim/vw-master"), "master")
	write(t, filepath.Join(home, ".local/state/scrim/ca/gen/1/key.pem"), "key")
	write(t, filepath.Join(outside, "signing.key"), "key")
	return outside, []OwnPath{
		{Path: filepath.Join(home, ".config/scrim/config.yaml"), Origin: "config file"},
		{Path: filepath.Join(home, ".config/scrim/vw-master"), Origin: "stores.vw.unlock"},
		{Path: filepath.Join(home, ".local/state/scrim"), Origin: "state directory"},
		{Path: filepath.Join(home, ".local/state/scrim/ca"), Origin: "tool-proxy.ca.dir"}, // inside the hidden state directory
		{Path: filepath.Join(outside, "signing.key"), Origin: "approvals.signing-key"},
		{Path: filepath.Join(outside, "missing"), Origin: "edge.ca.dir"}, // absent: skipped
		{Path: "relative/path", Origin: "x"},                             // not absolute: skipped
	}
}

// TestBuildNamespaceOwnFiles: the namespace view hides each readable own
// file wherever it is, a directory whole, and skips missing ones.
func TestBuildNamespaceOwnFiles(t *testing.T) {
	dir, sess, _ := home(t)
	outside, own := ownFiles(t, dir)
	p, err := Build(Input{Mode: ModeAuto, Available: yes, Home: dir, PasswdHome: dir, SessionDir: sess, Own: own,
		Keep: []string{sess, filepath.Join(sess, "api.sock")}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeNamespace {
		t.Fatalf("plan = %+v", p)
	}
	m := byTarget(p.Entries)
	for target, isDir := range map[string]bool{
		filepath.Join(dir, ".config/scrim/config.yaml"): false,
		filepath.Join(dir, ".config/scrim/vw-master"):   false,
		filepath.Join(dir, ".local/state/scrim"):        true,
		filepath.Join(outside, "signing.key"):           false,
	} {
		e, ok := m[target]
		if !ok || !e.Hidden() || !e.Own || e.Dir != isDir {
			t.Errorf("%s = %+v (present %v), want a hidden own entry, dir %v", target, e, ok, isDir)
		}
	}
	if len(m) != 4 {
		t.Errorf("entries = %v, want 4", m)
	}
}

// TestBuildOwnFilesUnreadableSkipped: a file the agent's user cannot read
// (a system service's 0600 file under another user) needs no cover.
func TestBuildOwnFilesUnreadableSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir, sess, _ := home(t)
	f := filepath.Join(t.TempDir(), "unlock")
	write(t, f, "x")
	if err := os.Chmod(f, 0); err != nil {
		t.Fatal(err)
	}
	p, err := Build(Input{Mode: ModeNamespace, Available: yes, Home: dir, PasswdHome: dir, SessionDir: sess,
		Own: []OwnPath{{Path: f, Origin: "stores.vw.unlock"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 {
		t.Errorf("unreadable own file covered: %+v", p.Entries)
	}
}

// TestBuildOwnFilesKeepWhatTheSessionNeeds: an own directory holding the
// session directory (or the API socket) cannot be hidden; the view refuses
// unless the weakening setting allows it.
func TestBuildOwnFilesKeepWhatTheSessionNeeds(t *testing.T) {
	dir, _, _ := home(t)
	state := t.TempDir()
	sess := filepath.Join(state, "run", "s1")
	if err := os.MkdirAll(sess, 0o700); err != nil {
		t.Fatal(err)
	}
	in := Input{Mode: ModeNamespace, Available: yes, Home: dir, PasswdHome: dir, SessionDir: sess,
		Own: []OwnPath{{Path: state, Origin: "state directory"}}, Keep: []string{sess}}
	if _, err := Build(in); err == nil || !strings.Contains(err.Error(), "which the session needs") ||
		!strings.Contains(err.Error(), AllowReadableOwn.Name()) {
		t.Fatalf("want a refusal naming the setting, got %v", err)
	}
	in.AllowReadableOwn = true
	p, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byTarget(p.Entries)[state]; ok || len(p.Exposed) != 1 {
		t.Errorf("entries %+v, exposed %v", p.Entries, p.Exposed)
	}
}

// TestHomeMirrorOwnFiles: the home mirror leaves out own files under $HOME,
// and refuses one outside it, which it cannot hide, unless allowed.
func TestHomeMirrorOwnFiles(t *testing.T) {
	dir, sess, _ := home(t)
	outside, own := ownFiles(t, dir)
	in := Input{Mode: ModeHome, Home: dir, SessionDir: sess, Own: own, Keep: []string{sess}}
	_, err := Build(in)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(outside, "signing.key")) || !strings.Contains(err.Error(), "outside $HOME") {
		t.Fatalf("want a refusal naming the file outside $HOME, got %v", err)
	}
	in.AllowReadableOwn = true
	p, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Exposed) != 1 || !strings.Contains(p.Exposed[0], "signing.key") {
		t.Errorf("exposed = %v", p.Exposed)
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".config/scrim/config.yaml", ".config/scrim/vw-master", ".local/state/scrim/ca/gen/1/key.pem"} {
		if _, err := os.ReadFile(filepath.Join(p.SessionHome, rel)); err == nil {
			t.Errorf("%s readable in the session home", rel)
		}
	}
	if b, err := os.ReadFile(filepath.Join(p.SessionHome, "work/main.go")); err != nil || string(b) != "package main" {
		t.Errorf("the rest of the home changed: %q %v", b, err)
	}
	// Only readable own files under $HOME: no refusal.
	if _, err := Build(Input{Mode: ModeHome, Home: dir, SessionDir: sess, Own: own[:3]}); err != nil {
		t.Errorf("own files under $HOME refused: %v", err)
	}
}
