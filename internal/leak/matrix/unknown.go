// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/leak"
)

// UnknownFormat is a secret that is in no store: a value in a known format
// an agent finds in a file, generated fresh for each run and never written to
// the seed file, so only scrim's fallback detectors can stop it.
type UnknownFormat struct {
	// ID is stable and used in row IDs.
	ID string
	// Command is a representative command printing the value.
	Command string
	// Expect is redacted for formats a default detector covers.
	Expect Expect
	// Note explains a limitation.
	Note string
	// Generate returns a fresh fake value, the tool output around it and
	// the parts of the value fixed by its format.
	Generate func() (value, before, after string, public []string)
}

const (
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	urlsafe  = alnum + "-_"
	b64chars = alnum + "+/"
	hexLower = "0123456789abcdef"
	b32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	letters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var rs = leak.RandString

// prefixed is a value made of a fixed vendor prefix and a random body. The
// prefix is joined at run time, so no token-shaped literal is committed.
func prefixed(prefix, body, before string) func() (string, string, string, []string) {
	return func() (string, string, string, []string) {
		return prefix + body, before, "\nLOG_LEVEL=debug\n", []string{prefix}
	}
}

// mixed draws n characters of alphabet that hold an upper case letter, a
// lower case letter and a digit, as a real random key does.
func mixed(alphabet string, n int) string {
	for {
		s := rs(alphabet, n)
		if strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(s, "0123456789") {
			return s
		}
	}
}

const envHead = "$ cat .env\n# billing service\nSERVICE_NAME=billing\n"

// UnknownFormats is the unknown-secret catalogue.
var UnknownFormats = []UnknownFormat{
	{ID: "aws-secret-access-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return mixed(b64chars, 40), envHead + "AWS_ACCESS_KEY_ID=AKIA" + rs(b32chars, 16) + "\nAWS_SECRET_ACCESS_KEY=", "\nAWS_REGION=eu-west-1\n", nil
	}},
	{ID: "aws-credentials-csv", Command: "cat credentials.csv", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return mixed(b64chars, 40), "$ cat credentials.csv\nUser name,Password,Access key ID,Secret access key\nci,,AKIA" + rs(b32chars, 16) + ",", "\n", nil
	}},
	{ID: "github-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("ghp_", rs(alnum, 36), envHead+"GITHUB_TOKEN=")()
	}},
	{ID: "github-fine-grained-token", Command: "gh auth status -t", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("github_pat_", rs(alnum, 22)+"_"+rs(alnum, 59), "$ gh auth status -t\n  - Token: ")()
	}},
	{ID: "gitlab-token", Command: "cat ~/.config/glab-cli/config.yml", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("glpat-", rs(urlsafe, 20), "hosts:\n  gitlab.com:\n    token: ")()
	}},
	{ID: "slack-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("xoxb-", rs("0123456789", 12)+"-"+rs("0123456789", 12)+"-"+rs(alnum, 24), envHead+"SLACK_BOT_TOKEN=")()
	}},
	{ID: "slack-webhook-url", Command: "cat alerting.yaml", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("hooks.slack.com/services/", "T"+rs(b32chars, 10)+"/B"+rs(b32chars, 10)+"/"+rs(alnum, 24), "receivers:\n- slack_configs:\n  - api_url: https://")()
	}},
	{ID: "stripe-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("sk_live_", rs(alnum, 32), envHead+"STRIPE_SECRET_KEY=")()
	}},
	{ID: "google-api-key", Command: "cat config.js", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("AIza", rs(urlsafe, 35), "export const firebase = { apiKey: \"")()
	}},
	{ID: "openai-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("sk-proj-", rs(urlsafe, 64), envHead+"OPENAI_API_KEY=")()
	}},
	{ID: "anthropic-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("sk-ant-api03-", rs(urlsafe, 93)+"AA", envHead+"ANTHROPIC_API_KEY=")()
	}},
	{ID: "npm-token", Command: "cat ~/.npmrc", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("npm_", rs(alnum, 36), "//registry.npmjs.org/:_authToken=")()
	}},
	{ID: "pypi-token", Command: "cat ~/.pypirc", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("pypi-AgEIcHlwaS5vcmc", rs(urlsafe, 120), "[pypi]\nusername = __token__\npassword = ")()
	}},
	{ID: "docker-hub-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("dckr_pat_", rs(urlsafe, 27), envHead+"DOCKERHUB_TOKEN=")()
	}},
	{ID: "huggingface-token", Command: "cat ~/.cache/huggingface/token", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("hf_", "Qx"+rs(letters, 32), "$ cat ~/.cache/huggingface/token\n")()
	}},
	{ID: "twilio-auth-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return rs(hexLower, 32), envHead + "TWILIO_ACCOUNT_SID=AC" + rs(hexLower, 32) + "\nTWILIO_AUTH_TOKEN=", "\n", nil
	}},
	{ID: "sendgrid-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("SG.", rs(urlsafe, 22)+"."+rs(urlsafe, 43), envHead+"SENDGRID_API_KEY=")()
	}},
	{ID: "azure-storage-key", Command: "cat appsettings.json", Expect: Redacted, Generate: func() (string, string, string, []string) {
		b := []byte(rs(alnum, 64))
		return base64.StdEncoding.EncodeToString(b), `{"Storage": "DefaultEndpointsProtocol=https;AccountName=billing;AccountKey=`, `;EndpointSuffix=core.windows.net"}`, nil
	}},
	{ID: "digitalocean-token", Command: "cat ~/.config/doctl/config.yaml", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("dop_v1_", rs(hexLower, 64), "access-token: ")()
	}},
	{ID: "shopify-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("shpat_", rs(hexLower, 32), envHead+"SHOPIFY_ACCESS_TOKEN=")()
	}},
	{ID: "atlassian-api-token", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("ATATT3", rs(urlsafe, 186), envHead+"JIRA_API_TOKEN=")()
	}},
	{ID: "database-url-password", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return mixed(alnum, 24), envHead + "DATABASE_URL=postgres://billing:", "@db.internal:5432/billing\n", nil
	}},
	{ID: "private-key", Command: "cat id_ed25519", Expect: Redacted, Generate: func() (string, string, string, []string) {
		// The armour is joined at run time so the source holds no key-shaped block.
		label := "OPENSSH PRIVATE" + " KEY-----"
		begin, end := "-----BEGIN "+label+"\n", "\n-----END "+label
		body := rs(b64chars, 280)
		var b strings.Builder
		b.WriteString(begin)
		for i := 0; i < len(body); i += 70 {
			b.WriteString(body[i:min(i+70, len(body))])
			if i+70 < len(body) {
				b.WriteByte('\n')
			}
		}
		b.WriteString(end)
		return b.String(), "$ cat ~/.ssh/id_ed25519\n", "\n", []string{begin, end}
	}},
	{ID: "groq-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("gsk_", rs(alnum, 52), envHead+"GROQ_API_KEY=")()
	}},
	{ID: "xai-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("xai-", rs(alnum, 80), envHead+"XAI_API_KEY=")()
	}},
	{ID: "openrouter-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("sk-or-v1-", rs(hexLower, 64), envHead+"OPENROUTER_API_KEY=")()
	}},
	{ID: "aws-bedrock-api-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		// "ABSK" and the base64 of "BedrockAPIKey-", joined at run time.
		return prefixed("ABSK"+"QmVkcm9ja0FQSUtleS", rs(b64chars, 110), envHead+"AWS_BEARER_TOKEN_BEDROCK=")()
	}},
	{ID: "tailscale-key", Command: "cat .env", Expect: Redacted, Generate: func() (string, string, string, []string) {
		return prefixed("tskey-auth-", "k"+rs(alnum, 10)+"CNTRL-"+rs(alnum, 32), envHead+"TS_AUTHKEY=")()
	}},
	{ID: "random-password", Command: "cat .env", Expect: Limitation,
		Note: "limitation: a secret in no store and in no known format is not matched by default (redaction.detectors.entropy.enabled covers values after a key name that says secret, off by default)",
		Generate: func() (string, string, string, []string) {
			return mixed(alnum, 20), envHead + "SESSION_SECRET=", "\n", nil
		}},
	{ID: "base64-encoded-token", Command: "kubectl get secret billing -o yaml", Expect: Limitation,
		Note: "limitation: detectors match a format as written by default (redaction.detectors.encoded decodes base64, hex and percent-encoding, off by default)",
		Generate: func() (string, string, string, []string) {
			tok := "ghp_" + rs(alnum, 36)
			return base64.StdEncoding.EncodeToString([]byte(tok)), "apiVersion: v1\nkind: Secret\ndata:\n  token: ", "\n", nil
		}},
}

// unknownSeed generates the value of an unknown-secret row and the tool
// output that carries it.
func unknownSeed(u *UnknownFormat) (leak.Seed, Content) {
	v, before, after, public := u.Generate()
	s := leak.NewSeed("unknown/"+u.ID, leak.Kind("unknown-"+u.ID), v, public...)
	return s, Content{Command: u.Command, Before: before, Value: v, After: after}
}

func unknownMarkdown() string {
	var b strings.Builder
	b.WriteString("\n| Unknown secret | Representative command | Expected | Note |\n| --- | --- | --- | --- |\n")
	for _, u := range UnknownFormats {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", u.ID, escapePipe(u.Command), u.Expect, escapePipe(u.Note))
	}
	return b.String()
}
