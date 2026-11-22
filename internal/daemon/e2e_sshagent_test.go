// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshagent"
	"github.com/heliopsy/scrim/internal/sshkeys"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// sshdImage is the base of the throwaway git server: OpenSSH and git are
// installed into it when the container starts.
const sshdImage = "docker.io/library/alpine:3.24.4"

// gitServer is a throwaway sshd with a bare repository at /srv/repo.git,
// reachable as git@127.0.0.1:<port>, that accepts one public key.
type gitServer struct {
	name, addr, port string
	hostKey          ssh.PublicKey
}

func startGitServer(t *testing.T, authorized ssh.PublicKey) *gitServer {
	t.Helper()
	if os.Getenv("SCRIM_TEST_PODMAN") == "0" {
		t.Skip("SCRIM_TEST_PODMAN=0")
	}
	skip := func(format string, a ...any) {
		t.Helper()
		if os.Getenv("SCRIM_TEST_PODMAN") == "1" {
			t.Fatalf(format, a...)
		}
		t.Skipf(format, a...)
	}
	for _, tool := range []string{"podman", "git", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			skip("%s not found", tool)
		}
	}
	image := sshdImage
	if v := os.Getenv("SCRIM_TEST_SSHD_IMAGE"); v != "" {
		image = v
	}
	g := &gitServer{name: podtest.Prefix() + "-sshd-" + podtest.RandHex(4)}
	script := `set -e
apk add --no-cache -q openssh-server git >/dev/null
ssh-keygen -A >/dev/null
adduser -D -s /usr/bin/git-shell git
echo 'git:*' | chpasswd -e >/dev/null
mkdir -p /home/git/.ssh
printf '%s\n' "$AUTHORIZED_KEY" > /home/git/.ssh/authorized_keys
chmod 700 /home/git/.ssh && chmod 600 /home/git/.ssh/authorized_keys
git init -q --bare -b main /srv/repo.git
chown -R git:git /home/git/.ssh /srv/repo.git
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
`
	out, err := exec.Command("podman", "run", "-d", "--rm", "--name", g.name, "--memory", "256m",
		"-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEY="+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authorized))),
		image, "sh", "-c", script).CombinedOutput()
	if err != nil {
		skip("podman run %s: %v: %s", image, err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", "-v", g.name).Run() })
	hp, err := exec.Command("podman", "port", g.name, "22/tcp").Output()
	if err != nil {
		t.Fatalf("podman port: %v", err)
	}
	g.addr = strings.TrimSpace(strings.Split(string(hp), "\n")[0])
	_, g.port, _ = net.SplitHostPort(g.addr)
	deadline := time.Now().Add(120 * time.Second)
	for !banner(g.addr) {
		if time.Now().After(deadline) {
			logs, _ := exec.Command("podman", "logs", "--tail", "30", g.name).CombinedOutput()
			skip("sshd in %s never answered:\n%s", g.name, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}
	pub, err := exec.Command("podman", "exec", g.name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").Output()
	if err != nil {
		t.Fatalf("reading the host key: %v", err)
	}
	if g.hostKey, _, _, _, err = ssh.ParseAuthorizedKey(pub); err != nil {
		t.Fatal(err)
	}
	return g
}

func banner(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "SSH-2.0-")
}

func (g *gitServer) log(t *testing.T) string {
	t.Helper()
	// Output only: podman warns on standard error on some hosts.
	out, err := exec.Command("podman", "exec", g.name, "git", "--git-dir=/srv/repo.git", "log", "--format=%s", "main").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// TestSSHAgentGitOverSSH runs git clone and git push over SSH to a
// throwaway sshd in rootless podman, signing with a key held only in a
// scrim store through scrim's ssh-agent. Every signature asks: approved
// signatures let clone and push through, and a denied one fails the push.
func TestSSHAgentGitOverSSH(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(blk))
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := startGitServer(t, signer.PublicKey())

	h := newHarness(t, seed(t, "sk-ssh-"))
	t.Setenv("SCRIMTEST_SSH_KEY", keyPEM)
	// scrim's own known_hosts names the server; the client's has its
	// address. Neither is writable by anything but this test.
	scrimKnown := filepath.Join(h.dir, "scrim_known_hosts")
	if err := os.WriteFile(scrimKnown, []byte("git.scrim.test "+string(ssh.MarshalAuthorizedKey(srv.hostKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	clientKnown := filepath.Join(h.dir, "known_hosts")
	if err := os.WriteFile(clientKnown, []byte("[127.0.0.1]:"+srv.port+" "+string(ssh.MarshalAuthorizedKey(srv.hostKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: git-over-ssh
    decision: ask
    when: >-
      op == "ssh.sign" && secret.name == "deploy" && ssh.kind == "userauth" &&
      ssh.user == "git" && dest.host == "git.scrim.test"
    reason: git over ssh to the test server
    grant: {scope: once}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(h.dir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	cfg = []byte(strings.Replace(string(cfg), "catalog:\n  entries:\n", "catalog:\n  entries:\n    deploy:\n      ref: testenv://SCRIMTEST_SSH_KEY\n      ssh_key: true\n", 1) +
		"ssh-agent:\n  known-hosts: [" + scrimKnown + "]\napprovals:\n  timeout: 20s\n")
	cfg = []byte(strings.Replace(string(cfg), "approvals:\n  timeout: 2s\n", "", 1))
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	eventually(t, "daemon ready", func() bool { return d.Ready(ctx) })

	mc := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	m, err := mc.Mint(ctx, localapi.MintInput{Name: "ssh-e2e"})
	mc.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Token.Wipe()

	// What scrim run gives the agent: SSH_AUTH_SOCK in the session
	// directory, served by an agent that asks the control plane, as this
	// session, for every key list and signature.
	sessDir, err := os.MkdirTemp("", "scrim-ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sessDir) }()
	plan, err := run.Build(run.Input{Command: []string{"git"}, Environ: []string{"SSH_AUTH_SOCK=/tmp/users-own-agent"},
		SessionDir: sessDir, SessionID: m.Session.ID, Token: true, SSHAgent: true,
		Endpoints: run.Endpoints{LLMBaseURL: d.Addrs().BaseURL}})
	if err != nil {
		t.Fatal(err)
	}
	sock := ""
	for _, v := range plan.Set {
		if v.Name == "SSH_AUTH_SOCK" {
			sock = v.Value
		}
	}
	if sock != filepath.Join(sessDir, run.FileSSHAgent) {
		t.Fatalf("SSH_AUTH_SOCK = %q", sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	api := localapi.NewClient(d.Addrs().AgentAPI, m.Token)
	defer api.Close()
	agentDone := make(chan error, 1)
	go func() { agentDone <- (&sshagent.Server{Backend: api}).Serve(ctx, ln) }()

	// The approver: settles each pending ssh.sign approval as told.
	var approve atomic.Bool
	var mu sync.Mutex
	var seen []state.Approval
	apps := d.App().PolicyParts.Approvals
	go func() {
		for ctx.Err() == nil {
			pending, err := apps.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
			if err == nil {
				for _, a := range pending {
					mu.Lock()
					seen = append(seen, a)
					mu.Unlock()
					_, _ = apps.Decide(ctx, a.ID, approval.Decision{Approve: approve.Load(), By: "e2e", Via: "api"})
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	home := t.TempDir()
	work := filepath.Join(home, "work")
	gitEnv := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "SSH_AUTH_SOCK=" + sock,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_SSH_COMMAND=ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + clientKnown,
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@scrim.test", "GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@scrim.test"}
	var outputs []string
	git := func(dir string, args ...string) error {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir, cmd.Env = dir, gitEnv
		out, err := cmd.CombinedOutput()
		outputs = append(outputs, string(out))
		if err != nil {
			return errors.New(strings.TrimSpace(string(out)))
		}
		return nil
	}
	commit := func(msg string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, "file.txt"), []byte(msg+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := git(work, "add", "file.txt"); err != nil {
			t.Fatal(err)
		}
		if err := git(work, "commit", "-q", "-m", msg); err != nil {
			t.Fatal(err)
		}
	}
	remote := "ssh://git@127.0.0.1:" + srv.port + "/srv/repo.git"

	approve.Store(true)
	if err := git(home, "clone", "-q", remote, work); err != nil {
		t.Fatalf("git clone: %v\n%s", err, h.logs.String())
	}
	if err := git(work, "checkout", "-q", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	commit("first")
	if err := git(work, "push", "-q", "origin", "main"); err != nil {
		t.Fatalf("approved git push: %v\n%s", err, h.logs.String())
	}
	if got := srv.log(t); got != "first" {
		t.Fatalf("the server has %q after the approved push", got)
	}

	approve.Store(false)
	commit("second")
	if err := git(work, "push", "-q", "origin", "main"); err == nil {
		t.Fatal("git push went through although its signature was denied")
	}
	if got := srv.log(t); got != "first" {
		t.Fatalf("the server has %q after the denied push", got)
	}

	// Each signature asked, and the approver saw what it was for.
	mu.Lock()
	asked := append([]state.Approval(nil), seen...)
	mu.Unlock()
	if len(asked) < 3 {
		t.Fatalf("%d approvals for clone, push and denied push", len(asked))
	}
	for _, a := range asked {
		r := a.Request
		if r.Action != policy.ActionSign || r.Name != "deploy" || r.Host != "git.scrim.test" || r.SSH.User != "git" ||
			r.SSH.HostKey != ssh.FingerprintSHA256(srv.hostKey) || r.SSH.Key != ssh.FingerprintSHA256(signer.PublicKey()) ||
			r.Agent.Session != m.Session.ID {
			t.Fatalf("approval for %+v", r)
		}
	}
	// Every signature is in the audit log, allowed and denied.
	var allowed, denied int
	entries, err := queryAudit(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Rule == sshkeys.RuleRefused {
			t.Errorf("a signature was refused before policy: %s", e.Reason)
		}
		if e.Action == gate.ActionDecision && e.Attrs["action"] == string(policy.ActionSign) {
			switch e.Effect {
			case policy.Allow:
				allowed++
			default:
				denied++
			}
			if e.Attrs["ssh_user"] != "git" || e.Target != "git.scrim.test" {
				t.Errorf("audit entry lacks the login: %+v", e)
			}
		}
	}
	if allowed < 2 || denied < 1 {
		t.Fatalf("audit: %d allowed, %d denied signatures", allowed, denied)
	}

	// The private key reached nothing: not git or ssh, not the logs, not
	// the audit log.
	raw, _ := json.Marshal(entries)
	hay := strings.Join(outputs, "\n") + h.logs.String() + string(raw)
	for _, line := range strings.Split(keyPEM, "\n") {
		if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(hay, line) {
			t.Fatal("the private key leaked")
		}
	}

	cancel()
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
}

func queryAudit(ctx context.Context, d *Daemon) ([]audit.Entry, error) {
	var out []audit.Entry
	err := d.App().State.View(ctx, func(tx state.Tx) error {
		var err error
		out, err = tx.QueryAudit(ctx, state.AuditQuery{Action: gate.ActionDecision})
		return err
	})
	return out, err
}
