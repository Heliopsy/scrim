// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// channel is the boundary connection on Windows, where a child cannot
// inherit a socket by descriptor number: two anonymous pipes that become
// the child's stdin and stdout. Only the two processes hold their ends
// (Go passes a child exactly the handles it is given), and nothing has a
// name another process could open. The data plane runs with --stdio and
// never writes anything else to stdout.
type channel struct {
	childIn, parentOut *os.File // control plane -> data plane
	parentIn, childOut *os.File // data plane -> control plane
}

func newChannel() (*channel, error) {
	cr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	pr, cw, err := os.Pipe()
	if err != nil {
		_ = cr.Close()
		_ = pw.Close()
		return nil, err
	}
	return &channel{childIn: cr, parentOut: pw, parentIn: pr, childOut: cw}, nil
}

func (c *channel) args() []string { return []string{"--stdio"} }

func (c *channel) env() []string { return []string{"SCRIM_DP_STDIO=1"} }

func (c *channel) attach(cmd *exec.Cmd) {
	cmd.Stdin = c.childIn
	cmd.Stdout = c.childOut
}

func (c *channel) closeChild() {
	_ = c.childIn.Close()
	_ = c.childOut.Close()
}

func (c *channel) closeParent() {
	_ = c.parentIn.Close()
	_ = c.parentOut.Close()
}

func (c *channel) conn() (net.Conn, error) {
	return &pipeConn{r: c.parentIn, w: c.parentOut}, nil
}

// pipeConn is a net.Conn over the two pipes. Closing it closes the write
// end first, which the data plane reads as EOF and exits on; the read end
// then returns EOF when the child's stdout closes.
type pipeConn struct {
	r, w *os.File
	once sync.Once
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }

func (p *pipeConn) Close() error {
	var err error
	p.once.Do(func() { err = errors.Join(p.w.Close(), p.r.Close()) })
	return err
}

func (p *pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }

// Anonymous pipes on Windows are synchronous handles without deadlines;
// gRPC works without them (its keepalive and stream deadlines are its own).
func (p *pipeConn) SetDeadline(time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }
