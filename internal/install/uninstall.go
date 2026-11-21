// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type outcome int

const (
	reverted outcome = iota
	// kept is a change uninstall leaves on purpose (state without --purge).
	kept
	// failed is a change that could not be reverted.
	failed
)

type result struct {
	outcome outcome
	err     error
	// manual is the step that reverts a kept or failed change by hand.
	manual string
}

func ok() result { return result{} }

func fail(err error, manual string) result { return result{outcome: failed, err: err, manual: manual} }

// holds reports whether the entry is a directory that contains path.
func holds(e Entry, path string) bool {
	if e.Kind != KindDir && e.Kind != KindState {
		return false
	}
	rel, err := filepath.Rel(e.Target, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..")
}

// Uninstall reverts every change the manifest lists, newest first. A change
// that cannot be reverted stays in the manifest and is reported with the
// manual step; then ErrNotReverted is returned. State directories, the
// podman volume and the pulled image are kept unless Purge is set.
func (in *Installer) Uninstall(ctx context.Context) error {
	in.mpath = in.ManifestPath()
	mf, found, err := ReadManifest(in.mpath)
	if err != nil {
		return err
	}
	if !found {
		in.printf("nothing to uninstall: no install is recorded in %s\n", in.mpath)
		return nil
	}
	in.mf = mf
	in.Mode, in.System, in.Image = mf.Mode, mf.System, mf.Image
	if in.DryRun {
		in.printf("scrim uninstall (%s) would revert, newest first:\n", describeMode(mf.Mode, mf.System))
	} else {
		in.printf("scrim uninstall (%s), reverting newest first:\n", describeMode(mf.Mode, mf.System))
	}

	var keptOrFailed []Entry
	var manual []string
	nfailed := 0
	// Directories holding the manifest go last, once it is removed.
	var last []Entry
	for i := len(mf.Entries) - 1; i >= 0; i-- {
		e := mf.Entries[i]
		if holds(e, in.mpath) {
			last = append(last, e)
			continue
		}
		r := in.revertOne(ctx, e)
		switch r.outcome {
		case reverted:
			if !in.DryRun {
				in.mf.Entries = deleteEntry(in.mf.Entries, e)
				if err := writeManifest(in.mpath, in.mf); err != nil {
					return err
				}
			}
		case kept:
			keptOrFailed = append(keptOrFailed, e)
			manual = append(manual, fmt.Sprintf("kept %s\n    to remove it: %s", e.Target, r.manual))
		case failed:
			nfailed++
			keptOrFailed = append(keptOrFailed, e)
			in.printf("  failed: %v\n", r.err)
			manual = append(manual, fmt.Sprintf("not reverted: %s\n    manual step: %s", e.Target, r.manual))
		}
	}

	// The manifest's own directories: removed once nothing else is left.
	switch {
	case in.DryRun:
		for _, e := range last {
			in.revertOne(ctx, e)
		}
	case len(keptOrFailed) == 0 && in.removable(last):
		if !in.DryRun {
			if err := os.Remove(in.mpath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("install: %w", err)
			}
		}
		for _, e := range last {
			r := in.revertOne(ctx, e)
			if r.outcome != reverted {
				nfailed++
				in.printf("  failed: %v\n", r.err)
				manual = append(manual, fmt.Sprintf("not reverted: %s\n    manual step: %s", e.Target, r.manual))
			}
		}
	default:
		for _, e := range last {
			if e.Kind == KindState && !in.Purge {
				manual = append(manual, fmt.Sprintf("kept %s\n    to remove it: scrim uninstall --%s --purge, or rm -r %s", e.Target, in.scope(), e.Target))
			}
		}
		if len(keptOrFailed) > 0 || len(last) > 0 {
			in.printf("  the manifest %s stays and lists what is left\n", in.mpath)
		}
	}

	if len(manual) > 0 {
		in.printf("\n%s\n", strings.Join(manual, "\n"))
	}
	if in.DryRun {
		in.printf("\nNothing was changed (dry run).\n")
	}
	if nfailed > 0 {
		return fmt.Errorf("%w: %d", ErrNotReverted, nfailed)
	}
	return nil
}

// removable reports whether the directories that hold the manifest can go:
// a state directory only with Purge or when it holds nothing but the
// manifest and the other listed directories.
func (in *Installer) removable(dirs []Entry) bool {
	for _, e := range dirs {
		if e.Kind == KindState && in.Purge {
			continue
		}
		empty, err := onlyHolds(e.Target, in.mpath, dirs, in.Purge)
		if err != nil || !empty {
			return false
		}
	}
	return true
}

// onlyHolds reports whether dir contains nothing but the manifest and the
// listed directories (themselves holding nothing else).
func onlyHolds(dir, manifest string, dirs []Entry, purge bool) (bool, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, de := range ents {
		p := filepath.Join(dir, de.Name())
		if p == manifest {
			continue
		}
		listed, purged := false, false
		for _, e := range dirs {
			if e.Target == p {
				listed = true
				purged = e.Kind == KindState && purge
			}
		}
		if !listed || !de.IsDir() {
			return false, nil
		}
		if purged {
			continue
		}
		if ok, err := onlyHolds(p, manifest, dirs, purge); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func deleteEntry(es []Entry, e Entry) []Entry {
	out := es[:0]
	for _, x := range es {
		if !x.same(e) {
			out = append(out, x)
		}
	}
	return out
}

func (in *Installer) revertOne(ctx context.Context, e Entry) result {
	desc, r := in.describeRevert(e)
	if r != nil {
		in.printf("- %s\n", desc)
		return *r
	}
	in.printf("- %s%s\n", in.verb(), desc)
	if in.DryRun {
		return ok()
	}
	return in.revert(ctx, e)
}

// describeRevert names the revert of e. A non-nil result means e is kept
// without trying (state without Purge).
func (in *Installer) describeRevert(e Entry) (string, *result) {
	purgeHint := fmt.Sprintf("scrim uninstall --%s --purge", in.scope())
	switch e.Kind {
	case KindGroup:
		return "delete the group " + e.Target + " (groupdel)", nil
	case KindUser:
		return "delete the user " + e.Target + " (userdel)", nil
	case KindMember:
		return fmt.Sprintf("remove %s from the group %s (gpasswd -d)", e.Target, e.Group), nil
	case KindDir:
		return "remove the directory " + e.Target + " if empty", nil
	case KindFile:
		return "remove " + e.Target, nil
	case KindService:
		if in.Mode == ModeQuadlet {
			return "stop " + e.Target + " (systemctl stop)", nil
		}
		return "stop and disable " + e.Target + " (systemctl disable --now)", nil
	case KindSystemTrust:
		return fmt.Sprintf("remove the scrim CA from the system trust store: %s, then %s", e.Target,
			strings.TrimSpace(e.Tool+" "+strings.Join(removeArgs(e.Tool), " "))), nil
	case KindUserTrust:
		return "remove the scrim CA from this user's trust stores (scrim ca uninstall --user):", nil
	case KindNFTable:
		return "delete the nftables table " + e.Target + " (nft delete table " + e.Target + ")", nil
	case KindHosts:
		return "remove the scrim block from " + e.Target, nil
	case KindJavaTrust:
		return fmt.Sprintf("remove the scrim CA from the Java truststore %s (keytool -delete -alias %s)", e.Target, JavaAlias), nil
	case KindState:
		if !in.Purge {
			return "keep the state directory " + e.Target + " (CA, keys, state and audit log)",
				&result{outcome: kept, manual: purgeHint + ", or rm -r " + e.Target}
		}
		return "remove the state directory " + e.Target + " and everything in it", nil
	case KindVolume:
		if !in.Purge {
			return "keep the podman volume " + e.Target + " (state)", &result{outcome: kept, manual: purgeHint + ", or podman volume rm " + e.Target}
		}
		return "remove the podman volume " + e.Target, nil
	case KindImage:
		if !in.Purge {
			return "keep the image " + e.Target, &result{outcome: kept, manual: purgeHint + ", or podman rmi " + e.Target}
		}
		return "remove the image " + e.Target, nil
	}
	return "unknown change " + e.Kind + " " + e.Target, &result{outcome: failed, err: fmt.Errorf("unknown change kind %q", e.Kind),
		manual: "revert " + e.Target + " by hand"}
}

func (in *Installer) revert(ctx context.Context, e Entry) result {
	switch e.Kind {
	case KindGroup:
		if _, exists, err := in.group(e.Target); err != nil || !exists {
			return resultOf(err, "groupdel "+e.Target)
		}
		return resultOf(in.run(ctx, "groupdel", e.Target), "groupdel "+e.Target)
	case KindUser:
		if _, exists, err := in.user(e.Target); err != nil || !exists {
			return resultOf(err, "userdel "+e.Target)
		}
		return resultOf(in.run(ctx, "userdel", e.Target), "userdel "+e.Target)
	case KindMember:
		is, err := in.member(e.Target, e.Group)
		if err != nil || !is {
			return resultOf(err, "gpasswd -d "+e.Target+" "+e.Group)
		}
		return resultOf(in.run(ctx, "gpasswd", "-d", e.Target, e.Group), "gpasswd -d "+e.Target+" "+e.Group)
	case KindDir:
		err := os.Remove(e.Target)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return ok()
		}
		return fail(fmt.Errorf("%s is not empty or cannot be removed: %w", e.Target, err), "rm -r "+e.Target+" once nothing in it is needed")
	case KindFile:
		r := in.removeFile(e)
		if r.outcome == reverted && e.Reload != "" {
			if err := in.systemctl(ctx, e.Reload, "daemon-reload"); err != nil {
				in.printf("  daemon-reload failed: %v\n", err)
			}
		}
		return r
	case KindService:
		return in.stopService(ctx, e)
	case KindSystemTrust:
		anchor, _ := os.ReadFile(e.Target) // #nosec G304 -- recorded trust anchor
		r := in.removeFile(e)
		if r.outcome != reverted {
			return r
		}
		args := removeArgs(e.Tool)
		r = resultOf(in.run(ctx, e.Tool, args...), strings.TrimSpace(e.Tool+" "+strings.Join(args, " ")))
		if r.outcome == reverted && len(anchor) > 0 {
			in.checkManagedJava(ctx, string(anchor))
		}
		return r
	case KindNFTable:
		manual := "nft delete table " + e.Target
		if in.run(ctx, "nft", "list", "table", "inet", "scrim") != nil {
			return ok()
		}
		return resultOf(in.run(ctx, "nft", "delete", "table", "inet", "scrim"), manual)
	case KindHosts:
		return in.removeHostsBlock(e)
	case KindJavaTrust:
		return in.revertJava(ctx, e)
	case KindUserTrust:
		return resultOf(in.trust().Uninstall(ctx, false), "scrim ca uninstall --user")
	case KindState:
		return resultOf(os.RemoveAll(e.Target), "rm -r "+e.Target)
	case KindVolume:
		if in.podman(ctx, "volume", "exists", e.Target) != nil {
			return ok()
		}
		return resultOf(in.podman(ctx, "volume", "rm", e.Target), "podman volume rm "+e.Target)
	case KindImage:
		if in.podman(ctx, "image", "exists", e.Target) != nil {
			return ok()
		}
		return resultOf(in.podman(ctx, "rmi", e.Target), "podman rmi "+e.Target)
	}
	return fail(fmt.Errorf("unknown change kind %q", e.Kind), "revert "+e.Target+" by hand")
}

func resultOf(err error, manual string) result {
	if err != nil {
		return fail(err, manual)
	}
	return ok()
}

// removeFile removes a file while it still holds what install wrote.
func (in *Installer) removeFile(e Entry) result {
	cur, err := fileSum(e.Target)
	if errors.Is(err, fs.ErrNotExist) {
		return ok()
	}
	if err != nil {
		return fail(err, "rm "+e.Target)
	}
	if e.SHA256 != "" && cur != e.SHA256 {
		return fail(fmt.Errorf("%s was changed since scrim installed it; left alone", e.Target), "rm "+e.Target+" (check whether you still need the changes)")
	}
	if err := os.Remove(e.Target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail(err, "rm "+e.Target)
	}
	return ok()
}

func (in *Installer) stopService(ctx context.Context, e Entry) result {
	args := []string{"disable", "--now", e.Target}
	manual := "systemctl disable --now " + e.Target
	if in.Mode == ModeQuadlet {
		args = []string{"stop", e.Target}
		manual = "systemctl stop " + e.Target
	}
	if e.Scope == ScopeUser {
		manual = strings.Replace(manual, "systemctl ", "systemctl --user ", 1)
	}
	err := in.systemctl(ctx, e.Scope, args...)
	if err == nil {
		return ok()
	}
	// A unit that is gone already counts as reverted.
	out, qerr := in.Runner.Run(ctx, "systemctl", scoped(e.Scope, "show", "--property=LoadState", "--value", e.Target)...)
	if qerr == nil && strings.TrimSpace(string(out)) == "not-found" {
		return ok()
	}
	return fail(err, manual)
}

func scoped(scope string, args ...string) []string {
	if scope == ScopeUser {
		return append([]string{"--user"}, args...)
	}
	return args
}
