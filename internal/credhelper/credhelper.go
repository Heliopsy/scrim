// SPDX-License-Identifier: AGPL-3.0-only

// Package credhelper implements scrim's credential helpers for command-line
// tools (specs/credential-injection, "Credential helpers"; tasks 10a.9): the
// git credential helper protocol, the docker credential helper protocol, the
// AWS `credential_process` output and the kubectl exec plugin
// (client.authentication.k8s.io ExecCredential).
//
// A helper only ever returns what a tool profile generated for the session,
// which is placeholders: git and docker read the session's generated
// credential file named on the command line or by DOCKER_CONFIG, AWS and
// kubectl take the placeholders as arguments written into the generated
// configuration. A helper never reads a store, the real home directory's
// credential files or the network, and never stores what a tool hands it:
// `store` succeeds only for the credential it already returns, so a real
// password typed into `docker login` is refused instead of being kept.
//
// `scrim credential-helper <git|docker|aws|kubectl>` runs [Main]; scrim
// started as `docker-credential-scrim` (a link in the session's bin
// directory) runs the docker helper.
package credhelper

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DockerBinary is the name docker and containers/image run for the
// credential helper "scrim" (credsStore or credHelpers).
const DockerBinary = "docker-credential-scrim"

// Binaries are the names scrim answers to as a credential helper, the only
// names a tool profile may link into the session's bin directory.
var Binaries = []string{DockerBinary}

// errNotFound is the docker protocol's not-found answer, matched by docker
// and containers/image on stdout.
const dockerNotFound = "credentials not found in native keychain"

// Main runs the helper named by args[0] and returns the exit code. environ
// is the helper's environment (for DOCKER_CONFIG).
func Main(args []string, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: scrim credential-helper <git|docker|aws|kubectl> [args]")
		return 2
	}
	var err error
	switch args[0] {
	case "git":
		err = gitMain(args[1:], stdin, stdout)
	case "docker":
		err = dockerMain(args[1:], environ, stdin, stdout)
	case "aws":
		err = awsMain(args[1:], stdout)
	case "kubectl":
		err = kubeMain(args[1:], environ, stdout)
	default:
		err = fmt.Errorf("unknown credential helper %q (git, docker, aws, kubectl)", args[0])
	}
	if err != nil {
		var nf notFound
		if errors.As(err, &nf) {
			_, _ = fmt.Fprintln(stdout, dockerNotFound)
			return 1
		}
		_, _ = fmt.Fprintln(stderr, "scrim credential-helper: "+err.Error())
		return 1
	}
	return 0
}

type notFound struct{}

func (notFound) Error() string { return dockerNotFound }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// gitMain is a git credential helper: `get` answers from the generated
// credential store file (`https://user:placeholder@host` lines); `store`
// and `erase` change nothing.
func gitMain(args []string, in io.Reader, out io.Writer) error {
	fs := newFlags("git")
	file := fs.String("file", "", "the session's generated git-credentials file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("git: --file is required")
	}
	action := fs.Arg(0)
	req := map[string]string{}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			req[k] = v
		}
	}
	if action != "get" {
		// git calls store after a success and erase after a failure; the
		// file is the session's and holds placeholders, so neither changes it.
		return nil
	}
	if req["protocol"] != "https" && req["protocol"] != "http" {
		return nil
	}
	creds, err := readGitStore(*file)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if c.scheme == req["protocol"] && strings.EqualFold(c.host, req["host"]) && (req["username"] == "" || req["username"] == c.user) {
			_, err := fmt.Fprintf(out, "username=%s\npassword=%s\n", c.user, c.pass)
			return err
		}
	}
	return nil // git tries its next helper, or fails with prompts off
}

type gitCred struct{ scheme, host, user, pass string }

func readGitStore(path string) ([]gitCred, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the session's generated file, named in the git config scrim run set
	if err != nil {
		return nil, fmt.Errorf("git: reading the generated credential file: %w", errors.Unwrap(err))
	}
	var out []gitCred
	for _, line := range strings.Split(string(data), "\n") {
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil || u.User == nil || u.Host == "" {
			continue
		}
		pass, _ := u.User.Password()
		out = append(out, gitCred{scheme: u.Scheme, host: u.Host, user: u.User.Username(), pass: pass})
	}
	return out, nil
}

// dockerCred is the docker credential helper protocol's credential.
type dockerCred struct {
	ServerURL string `json:"ServerURL"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

// dockerMain is a docker credential helper over the auths of the session's
// generated config.json ($DOCKER_CONFIG/config.json). There is no default
// path: outside a session it knows no credentials.
func dockerMain(args []string, environ []string, in io.Reader, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("docker: usage: docker-credential-scrim <get|list|store|erase>")
	}
	dir := ""
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "DOCKER_CONFIG="); ok {
			dir = v
		}
	}
	auths := map[string]dockerCred{}
	if dir != "" {
		var err error
		if auths, err = readDockerAuths(filepath.Join(dir, "config.json")); err != nil {
			return err
		}
	}
	lookup := func(server string) (dockerCred, bool) {
		want := registryHost(server)
		for k, c := range auths {
			if registryHost(k) == want {
				c.ServerURL = server
				return c, true
			}
		}
		return dockerCred{}, false
	}
	switch args[0] {
	case "get":
		b, err := io.ReadAll(io.LimitReader(in, 4096))
		if err != nil {
			return err
		}
		c, ok := lookup(strings.TrimSpace(string(b)))
		if !ok {
			return notFound{}
		}
		return json.NewEncoder(out).Encode(c)
	case "list":
		m := map[string]string{}
		for k, c := range auths {
			m[k] = c.Username
		}
		return json.NewEncoder(out).Encode(m)
	case "store":
		var c dockerCred
		dec := json.NewDecoder(io.LimitReader(in, 1<<16))
		err := dec.Decode(&c)
		have, ok := lookup(c.ServerURL)
		same := err == nil && ok && have.Username == c.Username && have.Secret == c.Secret
		c.Secret = ""
		if same {
			return nil // the placeholder it already returns
		}
		return errors.New("docker: scrim's credential helper does not store credentials; put the registry credential in a " +
			"store and name it in the catalog (tools: [docker]), and scrim injects it")
	case "erase":
		return nil
	}
	return fmt.Errorf("docker: unknown action %q (get, list, store, erase)", args[0])
}

func readDockerAuths(path string) (map[string]dockerCred, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the session's generated docker config
	if errors.Is(err, os.ErrNotExist) {
		return map[string]dockerCred{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("docker: reading the generated config: %w", errors.Unwrap(err))
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, errors.New("docker: the generated config is not valid JSON")
	}
	out := map[string]dockerCred{}
	for k, a := range cfg.Auths {
		raw, err := base64.StdEncoding.DecodeString(a.Auth)
		if err != nil {
			continue
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			continue
		}
		out[k] = dockerCred{ServerURL: k, Username: user, Secret: pass}
	}
	return out, nil
}

// registryHost reduces a server URL ("https://index.docker.io/v1/",
// "registry.example.com:5000/v2") to its host.
func registryHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	s, _, _ = strings.Cut(s, "/")
	if slices.Contains([]string{"docker.io", "index.docker.io", "registry-1.docker.io"}, s) {
		return "docker.io"
	}
	return s
}

// awsMain prints the AWS credential_process answer from its arguments,
// which the aws profile writes into the generated config: placeholders.
func awsMain(args []string, out io.Writer) error {
	fs := newFlags("aws")
	id := fs.String("access-key-id", "", "")
	sec := fs.String("secret-access-key", "", "")
	tok := fs.String("session-token", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *sec == "" {
		return errors.New("aws: --access-key-id and --secret-access-key are required")
	}
	v := map[string]any{"Version": 1, "AccessKeyId": *id, "SecretAccessKey": *sec}
	if *tok != "" {
		v["SessionToken"] = *tok
	}
	return json.NewEncoder(out).Encode(v)
}

// kubeMain is a kubectl exec credential plugin printing an ExecCredential
// with the bearer token from its arguments, a placeholder.
func kubeMain(args []string, environ []string, out io.Writer) error {
	fs := newFlags("kubectl")
	tok := fs.String("token", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tok == "" {
		return errors.New("kubectl: --token is required")
	}
	api := "client.authentication.k8s.io/v1"
	info := ""
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "KUBERNETES_EXEC_INFO="); ok {
			info = v
		}
	}
	if info != "" {
		var ei struct {
			APIVersion string `json:"apiVersion"`
		}
		if json.Unmarshal([]byte(info), &ei) == nil && ei.APIVersion != "" {
			api = ei.APIVersion
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"apiVersion": api, "kind": "ExecCredential", "status": map[string]any{"token": *tok},
	})
}
