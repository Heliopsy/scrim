// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// Capture limits.
const (
	DefaultCaptureTimeout = 60 * time.Second
	MaxCaptureTimeout     = 10 * time.Minute
	// MaxCaptureOutput bounds what is read from a captured command.
	MaxCaptureOutput = 1 << 20
	// MaxValueSize bounds a value stored through any tool.
	MaxValueSize = 64 << 10
)

// CheckCapture validates a secret_capture input before anything runs.
func CheckCapture(in CaptureInput) error {
	if err := checkRef(in.Ref); err != nil {
		return err
	}
	if err := checkStore(in.Store); err != nil {
		return err
	}
	if len(in.Command) == 0 || in.Command[0] == "" {
		return Errorf(CodeInvalid, "command is required")
	}
	if in.TimeoutSeconds < 0 || time.Duration(in.TimeoutSeconds)*time.Second > MaxCaptureTimeout {
		return Errorf(CodeInvalid, "timeout_seconds must be between 0 and %d", int(MaxCaptureTimeout/time.Second))
	}
	return Extraction{JSONPath: in.JSONPath, Pattern: in.Pattern}.Check()
}

// RunCapture runs the command of a secret_capture and extracts the value
// from its standard output. It runs in the tool process, on the agent's side
// of the local socket. Standard input is empty, standard error is discarded,
// and no part of either output is ever returned or put into an error: a
// failing command is reported by exit status only.
func RunCapture(ctx context.Context, in CaptureInput) (secret.Value, int, error) {
	if err := CheckCapture(in); err != nil {
		return secret.Value{}, -1, err
	}
	timeout := DefaultCaptureTimeout
	if in.TimeoutSeconds > 0 {
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, in.Command[0], in.Command[1:]...) // #nosec G204 -- the agent names the command it wants captured; it runs as the agent
	cmd.Dir = in.Dir
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	out := &capped{limit: MaxCaptureOutput}
	cmd.Stdout = out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	defer out.wipe()

	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	switch {
	case ctx.Err() != nil:
		return secret.Value{}, code, Errorf(CodeInvalid, "command did not finish within %s; its output is withheld", timeout)
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist):
		return secret.Value{}, code, Errorf(CodeInvalid, "command %q was not found", in.Command[0])
	case err != nil && code < 0:
		return secret.Value{}, code, Errorf(CodeInvalid, "command %q could not be started", in.Command[0])
	case code != 0:
		return secret.Value{}, code, Errorf(CodeInvalid, "command exited with status %d; its output is withheld and nothing was stored", code)
	case out.over:
		return secret.Value{}, code, Errorf(CodeInvalid, "command output is larger than %d bytes; nothing was stored", MaxCaptureOutput)
	}
	v, err := Extraction{JSONPath: in.JSONPath, Pattern: in.Pattern}.Extract(out.Bytes())
	if err != nil {
		return secret.Value{}, code, err
	}
	if v.Len() > MaxValueSize {
		v.Wipe()
		return secret.Value{}, code, Errorf(CodeInvalid, "the extracted value is larger than %d bytes", MaxValueSize)
	}
	return v, code, nil
}

// capped collects up to limit bytes and drops the rest. When it grows, it
// wipes the buffer it leaves behind, so no stray copy of the output stays in
// memory.
type capped struct {
	b     []byte
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.limit - len(c.b); len(p) > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	if len(c.b)+len(p) > cap(c.b) {
		grown := make([]byte, len(c.b), max(2*cap(c.b), len(c.b)+len(p), 4096))
		copy(grown, c.b)
		secret.WipeBytes(c.b)
		c.b = grown
	}
	c.b = append(c.b, p...)
	return n, nil
}

func (c *capped) Bytes() []byte { return c.b }

func (c *capped) wipe() { secret.WipeBytes(c.b[:cap(c.b)]) }

// ReadValue reads a value from r, as `scrim secret put --stdin` does. It
// removes one trailing line ending unless keepNewline is set, and refuses an
// empty value or one larger than MaxValueSize.
func ReadValue(r io.Reader, keepNewline bool) (secret.Value, error) {
	buf := make([]byte, 0, 512)
	lr := io.LimitReader(r, MaxValueSize+3)
	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), 2*cap(buf))
			copy(grown, buf)
			secret.WipeBytes(buf)
			buf = grown
		}
		n, err := lr.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			secret.WipeBytes(buf)
			return secret.Value{}, Errorf(CodeInvalid, "reading the value failed")
		}
	}
	if !keepNewline {
		switch {
		case bytes.HasSuffix(buf, []byte("\r\n")):
			secret.WipeBytes(buf[len(buf)-2:])
			buf = buf[:len(buf)-2]
		case bytes.HasSuffix(buf, []byte("\n")):
			buf[len(buf)-1] = 0
			buf = buf[:len(buf)-1]
		}
	}
	if len(buf) > MaxValueSize {
		secret.WipeBytes(buf)
		return secret.Value{}, Errorf(CodeInvalid, "the value is larger than %d bytes", MaxValueSize)
	}
	if len(buf) == 0 {
		return secret.Value{}, Errorf(CodeInvalid, "no value was given")
	}
	return secret.Adopt(buf), nil
}

// CaptureReader extracts a value from up to MaxCaptureOutput bytes of r, as
// `scrim secret capture --stdin` does. Like RunCapture, no part of the input
// ever appears in an error.
func CaptureReader(r io.Reader, x Extraction) (secret.Value, error) {
	if err := x.Check(); err != nil {
		return secret.Value{}, err
	}
	out := &capped{limit: MaxCaptureOutput}
	defer out.wipe()
	if _, err := io.Copy(out, r); err != nil {
		return secret.Value{}, Errorf(CodeInvalid, "reading the input failed")
	}
	if out.over {
		return secret.Value{}, Errorf(CodeInvalid, "the input is larger than %d bytes; nothing was stored", MaxCaptureOutput)
	}
	v, err := x.Extract(out.Bytes())
	if err != nil {
		return secret.Value{}, err
	}
	if v.Len() > MaxValueSize {
		v.Wipe()
		return secret.Value{}, Errorf(CodeInvalid, "the extracted value is larger than %d bytes", MaxValueSize)
	}
	return v, nil
}
