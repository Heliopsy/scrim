// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/policy"
)

// The broker's own refusals, which no policy rule and no allow-list entry
// can lift (specs/credential-injection "Exec broker output is redacted").
// They are a backstop: what a command may receive is decided by the allow
// list and policy, which deny by default. These catch the commands and
// arguments that would hand a secret back in a form redaction may not
// recognise, or run code the agent chose with the secret in reach.

// transforms are program names that print, encode, split or reorder their
// input or environment, run other programs, or interpret code.
var transforms = map[string]string{}

func init() {
	for kind, names := range map[string][]string{
		"shell": {"sh", "bash", "dash", "zsh", "ksh", "mksh", "pdksh", "csh", "tcsh", "fish", "ash", "busybox", "toybox",
			"nu", "elvish", "xonsh", "pwsh", "powershell", "rbash", "yash", "oksh", "es", "rc"},
		"runs another program": {"env", "sudo", "doas", "su", "runuser", "nohup", "timeout", "nice", "ionice", "stdbuf",
			"setsid", "xargs", "parallel", "find", "watch", "script", "time", "strace", "ltrace", "gdb", "lldb", "chroot",
			"unshare", "nsenter", "flock", "taskset", "chrt", "systemd-run", "expect", "socat", "nc", "ncat", "netcat",
			"make", "gmake", "ninja", "cmake", "entr", "pkexec", "setpriv", "capsh", "prlimit", "ssh-agent", "dbus-run-session"},
		"prints or encodes": {"echo", "printf", "printenv", "cat", "tac", "nl", "rev", "base64", "base32", "basenc",
			"xxd", "od", "hexdump", "hd", "uuencode", "uudecode", "openssl", "gpg", "age", "tr", "cut", "fold", "fmt",
			"sed", "awk", "gawk", "mawk", "nawk", "dd", "split", "csplit", "paste", "column", "sort", "uniq", "head",
			"tail", "strings", "jq", "yq", "gojq", "grep", "egrep", "fgrep", "rg", "iconv", "recode", "tee", "pr",
			"expand", "unexpand", "shuf", "comm", "join", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum",
			"cksum", "sum", "gzip", "gunzip", "zcat", "bzip2", "xz", "zstd", "lz4", "compress", "zip", "tar", "cpio",
			"rot13", "figlet", "toilet", "cowsay", "logger", "wall", "write", "mail", "sendmail", "curl", "wget"},
		"interpreter": {"node", "nodejs", "deno", "bun", "java", "jshell", "groovy", "scala", "kotlin", "dotnet",
			"rscript", "julia", "osascript", "go", "gcc", "cc", "clang", "tcc", "npm", "npx", "yarn", "pnpm", "pip",
			"pip3", "pipx", "uv", "uvx", "gem", "bundle", "rake", "cargo", "rustc", "vim", "vi", "nvim", "emacs", "ed",
			"ex", "nano", "less", "more", "most", "man", "git-shell", "sqlite3", "bc", "dc", "m4"},
	} {
		for _, n := range names {
			transforms[n] = kind
		}
	}
}

// versioned matches interpreters with a version in their name (python3.12,
// perl5.36, lua5.4, php8.3, ruby3.2) and their bare forms.
var versioned = regexp.MustCompile(`^(python|perl|ruby|php|lua|luajit|tclsh|wish|pypy|jruby|irb|guile|racket|sbcl|ocaml|erl|escript|elixir|iex|ghci|runghc|swift)[0-9.]*$`)

// transformOf returns why a command must never be brokered, "" when it may.
// It looks at the name the agent used, the program path and, when the path
// is a link, the program it resolves to, so `python3` → `python3.12` and a
// busybox applet are both caught.
func transformOf(name string, path string) string {
	cands := []string{name, filepath.Base(path)}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		cands = append(cands, filepath.Base(real))
	}
	for _, c := range cands {
		c = strings.ToLower(strings.TrimSuffix(c, ".exe"))
		if k, ok := transforms[c]; ok {
			return k
		}
		if versioned.MatchString(c) {
			return "interpreter"
		}
	}
	return ""
}

// deniedEnv are variables an agent may never set, whatever a command's
// env-names says: each makes the dynamic loader, a shell or a common tool
// run code the agent chose, or points a tool at configuration it controls.
var deniedEnv = []string{
	"LD_*", "DYLD_*", "PATH", "HOME", "XDG_*", "IFS", "BASH_ENV", "ENV", "BASH_FUNC_*", "SHELLOPTS", "BASHOPTS",
	"PS4", "PROMPT_COMMAND", "NODE_OPTIONS", "NODE_PATH", "PYTHON*", "PERL5*", "PERLLIB", "RUBYOPT", "RUBYLIB",
	"GCONV_PATH", "LOCPATH", "GIT_*", "SSH_ASKPASS*", "SUDO_ASKPASS", "EDITOR", "VISUAL", "PAGER", "*_PAGER",
	"BROWSER", "KUBECONFIG", "TF_CLI_CONFIG_FILE", "TF_PLUGIN_CACHE_DIR", "OPENSSL_CONF", "OPENSSL_ENGINES",
	"MALLOC_*", "GLIBC_TUNABLES", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "SHELL", "TMPDIR",
}

func envDenied(name string) bool {
	return slices.ContainsFunc(deniedEnv, func(p string) bool { return policy.Glob(p, name) })
}

// toolRules harden well-known tools. Subcommands lists the first
// non-option arguments allowed (empty allows any); DenyArgs are argument
// prefixes refused anywhere; DenyContains are substrings refused in any
// argument; Env is set for the command before its own env.
type toolRules struct {
	Subcommands  []string
	DenyArgs     []string
	DenyArgsFor  map[string][]string
	DenyContains []string
	Env          map[string]string
}

// builtinTools are applied by the program's base name.
var builtinTools = map[string]toolRules{
	// Git reads hooks, aliases, helpers and ssh commands from the
	// repository's own configuration, which the agent can write. The
	// GIT_CONFIG_* variables have command-line scope, above every file, and
	// switch those off; options that would set them again are refused.
	"git": {
		Subcommands: []string{"push", "fetch", "ls-remote", "clone"},
		DenyArgs: []string{"-c", "-C", "--config-env", "--exec-path", "--upload-pack", "--receive-pack",
			"--template", "--signed", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config"},
		// -u is --upload-pack for these two (and harmless --set-upstream for push).
		DenyArgsFor:  map[string][]string{"clone": {"-u"}, "ls-remote": {"-u"}},
		DenyContains: []string{"ext::", "fd::"},
		Env: gitEnv(
			"core.hooksPath", "/dev/null",
			"core.fsmonitor", "false",
			"core.sshCommand", "ssh",
			"core.askPass", "",
			"core.pager", "cat",
			"core.editor", "false",
			"credential.helper", "",
			"protocol.allow", "never",
			"protocol.https.allow", "always",
			"protocol.ssh.allow", "always",
			"gpg.program", "false",
			"push.gpgSign", "false",
			"submodule.recurse", "false",
			"push.recurseSubmodules", "no",
			"fetch.recurseSubmodules", "false",
		),
	},
	// kubectl: no shell into workloads, no file copies, no local proxies,
	// no plugins and no other kubeconfig than the operator's.
	"kubectl": {
		DenyArgs: []string{"exec", "attach", "cp", "debug", "run", "port-forward", "proxy", "plugin", "config",
			"--kubeconfig", "--exec", "edit"},
	},
	// terraform: no console (it evaluates expressions over variables), no
	// changing directory past `dirs`.
	"terraform": {
		DenyArgs: []string{"console", "-chdir", "--chdir"},
	},
	"tofu": {
		DenyArgs: []string{"console", "-chdir", "--chdir"},
	},
}

func gitEnv(kv ...string) map[string]string {
	env := map[string]string{"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
	n := 0
	for i := 0; i+1 < len(kv); i += 2 {
		env["GIT_CONFIG_KEY_"+itoa(n)] = kv[i]
		env["GIT_CONFIG_VALUE_"+itoa(n)] = kv[i+1]
		n++
	}
	env["GIT_CONFIG_COUNT"] = itoa(n)
	return env
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// checkArgs applies a tool's rules to the agent's arguments. It returns the
// refused argument (which holds no value: arguments are checked before any
// placeholder is replaced) and why, or "" when they pass.
func (r toolRules) checkArgs(args []string) (string, string) {
	sub := ""
	for _, a := range args {
		if sub == "" && !strings.HasPrefix(a, "-") {
			sub = a
		}
	}
	for _, a := range args {
		for _, d := range slices.Concat(r.DenyArgs, r.DenyArgsFor[sub]) {
			if denies(d, a) {
				return a, "this argument is refused for the command"
			}
		}
		for _, d := range r.DenyContains {
			if strings.Contains(a, d) {
				return a, "this argument is refused for the command"
			}
		}
	}
	if len(r.Subcommands) > 0 && !slices.Contains(r.Subcommands, sub) {
		return sub, "only these subcommands are brokered: " + strings.Join(r.Subcommands, ", ")
	}
	return "", ""
}

// denies reports whether the refused option d matches argument a: exactly,
// as --opt=value, or as a short option with its value attached (-cfoo).
func denies(d, a string) bool {
	return a == d || strings.HasPrefix(a, d+"=") ||
		len(d) == 2 && d[0] == '-' && d[1] != '-' && strings.HasPrefix(a, d)
}
