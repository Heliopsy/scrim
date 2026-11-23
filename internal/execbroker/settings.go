// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
)

// Settings of the exec broker (specs/credential-injection "Exec broker").
var (
	// User is the identity brokered commands run as.
	User = config.Register(config.Spec[string]{
		Key: "exec.user",
		Description: "User name or numeric ID brokered commands run as, with that user's primary group and no supplementary groups. " +
			"Empty runs them as scrim's own user. scrim needs the right to switch users (root or CAP_SETUID and CAP_SETGID) when it is set. " +
			"A command never runs as root or as the calling agent's user.",
	})
	// AllowSameUser lets a command run as the caller's own user.
	AllowSameUser = config.Register(config.Spec[bool]{
		Key:       "exec.allow-same-user",
		Weakening: true,
		Description: "Run brokered commands even when they would run as the calling agent's own user. " +
			"That user can read the command's environment and memory (/proc/<pid>/environ, ptrace), so the agent can read the injected secret. For single-user development only.",
	})
	// Path is the PATH brokered commands get, and where a command that is
	// not on the allow list is looked up.
	Path = config.Register(config.Spec[string]{
		Key:         "exec.path",
		Default:     "/usr/local/bin:/usr/bin:/bin",
		Description: "PATH of brokered commands, and the directories a command that is not in exec.commands is looked up in. The agent's PATH is never used.",
		Validate: func(s string) error {
			for d := range strings.SplitSeq(s, ":") {
				if !filepath.IsAbs(d) {
					return fmt.Errorf("every directory must be absolute, not %q", d)
				}
			}
			return nil
		},
	})
	// Timeout is the default and maximum run time of a command.
	Timeout = config.Register(config.Spec[time.Duration]{
		Key:         "exec.timeout",
		Default:     2 * time.Minute,
		Description: "Longest a brokered command may run; a call can ask for less. The process group is killed when it runs out.",
		Validate: func(d time.Duration) error {
			if d <= 0 || d > time.Hour {
				return errors.New("must be between 1s and 1h")
			}
			return nil
		},
	})
	// MaxOutput bounds each output stream.
	MaxOutput = config.Register(config.Spec[int]{
		Key:     "exec.max-output",
		Default: 1 << 20,
		Description: "Largest standard output or standard error, in bytes, a brokered command may return. " +
			"A stream above it is withheld entirely, never cut, because a cut could split a secret past redaction.",
		Validate: func(n int) error {
			if n < 1024 || n > maxOutputLimit {
				return fmt.Errorf("must be between 1024 and %d", maxOutputLimit)
			}
			return nil
		},
	})
	// Commands is the allow list.
	Commands = config.RegisterCollection(config.CollectionSpec{
		Key: commandsKey,
		Description: "Commands the exec broker may run with secrets, by the name agents call them: `path` (absolute, required), " +
			"`secrets` (globs over store references or catalog names whose values the command may receive; its allow list), " +
			"`inject` (where placeholders are replaced: env, args, stdin; default env), `env-names` (globs of variables the agent may set), " +
			"`env` (fixed variables, not secret), `dirs` (globs of working directories the agent may choose; default none, a fresh empty directory), " +
			"`args` (regular expressions; the shell-quoted argument list must match one in full) and `timeout`.",
		RequiredFields: []string{"path", "secrets"},
		Validate: func(inst config.Instance) error {
			_, err := commandOf(inst)
			return err
		},
	})
)

const (
	commandsKey    = "exec.commands"
	maxOutputLimit = 3 << 20
)

// Location is where a placeholder may be replaced.
type Location string

// Locations.
const (
	InEnv   Location = "env"
	InArgs  Location = "args"
	InStdin Location = "stdin"
)

// Command is one allow-listed command.
type Command struct {
	Name     string
	Path     string
	Secrets  []string
	Inject   []Location
	EnvNames []string
	Env      map[string]string
	Dirs     []string
	Args     []*regexp.Regexp
	Timeout  time.Duration
}

// allowsSecret reports whether the command's allow list names the secret,
// by reference or catalog name.
func (c *Command) allowsSecret(ref, name string) bool {
	for _, p := range c.Secrets {
		if policy.Glob(p, ref) || name != "" && policy.Glob(p, name) {
			return true
		}
	}
	return false
}

func (c *Command) injects(l Location) bool { return slices.Contains(c.Inject, l) }

// Config is the broker configuration in force for one call.
type Config struct {
	User          string
	AllowSameUser bool
	Path          string
	Timeout       time.Duration
	MaxOutput     int
	Commands      map[string]*Command
}

// ConfigFrom reads the broker settings.
func ConfigFrom(cfg *config.Config) (Config, error) {
	out := Config{User: User.Get(cfg), AllowSameUser: AllowSameUser.Get(cfg), Path: Path.Get(cfg),
		Timeout: Timeout.Get(cfg), MaxOutput: MaxOutput.Get(cfg), Commands: map[string]*Command{}}
	for _, inst := range Commands.Get(cfg) {
		c, err := commandOf(inst)
		if err != nil {
			return Config{}, err
		}
		out.Commands[c.Name] = c
	}
	return out, nil
}

func commandOf(inst config.Instance) (*Command, error) {
	where := func(f string) string { return inst.Key(commandsKey, f) }
	for k := range inst.Fields {
		switch k {
		case "path", "secrets", "inject", "env-names", "env", "dirs", "args", "timeout":
		default:
			return nil, fmt.Errorf("%s.%s: unknown field %s", commandsKey, inst.Name, k)
		}
	}
	c := &Command{Name: inst.Name, Path: inst.String("path"), Inject: []Location{InEnv}}
	if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path {
		return nil, fmt.Errorf("%s: must be an absolute, clean path", where("path"))
	}
	if t := transformOf(inst.Name, c.Path); t != "" {
		return nil, fmt.Errorf("%s: %s can print or transform a secret (%s) and is never brokered", where("path"), c.Path, t)
	}
	var err error
	if c.Secrets, err = list(inst, "secrets"); err != nil || len(c.Secrets) == 0 {
		return nil, fmt.Errorf("%s: must list at least one reference, catalog name or glob", where("secrets"))
	}
	if raw, err := list(inst, "inject"); err != nil {
		return nil, fmt.Errorf("%s: %w", where("inject"), err)
	} else if raw != nil {
		c.Inject = nil
		for _, l := range raw {
			switch Location(l) {
			case InEnv, InArgs, InStdin:
				c.Inject = append(c.Inject, Location(l))
			default:
				return nil, fmt.Errorf("%s: %q is not env, args or stdin", where("inject"), l)
			}
		}
	}
	if c.EnvNames, err = list(inst, "env-names"); err != nil {
		return nil, fmt.Errorf("%s: %w", where("env-names"), err)
	}
	if c.Dirs, err = list(inst, "dirs"); err != nil {
		return nil, fmt.Errorf("%s: %w", where("dirs"), err)
	}
	for _, d := range c.Dirs {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("%s: %q is not absolute", where("dirs"), d)
		}
	}
	patterns, err := list(inst, "args")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where("args"), err)
	}
	for _, p := range patterns {
		re, err := regexp.Compile(`\A(?:` + p + `)\z`)
		if err != nil {
			return nil, fmt.Errorf("%s: %q does not compile", where("args"), p)
		}
		c.Args = append(c.Args, re)
	}
	if raw, ok := inst.Field("env"); ok {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: must be a map of names to values", where("env"))
		}
		c.Env = make(map[string]string, len(m))
		for k, v := range m {
			s, ok := v.(string)
			if !ok || !validEnvName(k) || strings.ContainsRune(s, 0) {
				return nil, fmt.Errorf("%s: %s must be a variable name with a string value", where("env"), k)
			}
			c.Env[k] = s
		}
	}
	if t := inst.String("timeout"); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d <= 0 || d > time.Hour {
			return nil, fmt.Errorf("%s: must be a duration between 1s and 1h", where("timeout"))
		}
		c.Timeout = d
	}
	return c, nil
}

func list(inst config.Instance, field string) ([]string, error) {
	raw, ok := inst.Field(field)
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		var out []string
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, errors.New("must be a list of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("must be a list of strings")
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// clone returns a copy of the fixed environment.
func (c *Command) fixedEnv() map[string]string { return maps.Clone(c.Env) }
