// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// prepare materialises b. Without fallback it uses a sealed memfd; with
// fallback, a hash-checked file under $XDG_RUNTIME_DIR/scrim (or the user
// cache directory when that is unset). Either way the child is executed
// through /proc/self/fd/N of a descriptor whose content was checked, so the
// file cannot be swapped between check and exec.
func prepare(b Binary, fallback bool) (*executable, error) {
	if !fallback {
		f, err := memfd(b.Image)
		if err == nil {
			return &executable{path: fdPath(f), keep: f, how: "memfd"}, nil
		}
		return nil, err
	}
	dir, err := fallbackDir()
	if err != nil {
		return nil, err
	}
	f, err := writeVerified(dir, b)
	if err != nil {
		return nil, err
	}
	return &executable{path: fdPath(f), keep: f, how: "file"}, nil
}

func fdPath(f *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(f.Fd())) }

func memfd(image []byte) (*os.File, error) {
	const name = "scrim-dataplane"
	flags := unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
	fd, err := unix.MemfdCreate(name, flags|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		// Kernels before 6.3 do not know MFD_EXEC; their memfds are
		// executable by default.
		fd, err = unix.MemfdCreate(name, flags)
	}
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := io.Copy(f, bytes.NewReader(image)); err != nil {
		_ = f.Close()
		return nil, err
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sealing memfd: %w", err)
	}
	return f, nil
}

func fallbackDir() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "scrim"), nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", errors.New("neither XDG_RUNTIME_DIR nor a user cache directory is available")
	}
	return filepath.Join(d, "scrim"), nil
}

// execRefused reports whether a start failed because the kernel would not
// execute the memfd, so the file fallback should be tried.
func execRefused(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOEXEC)
}

func checkOwner(fi os.FileInfo, dir string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by this user", dir)
	}
	return nil
}
