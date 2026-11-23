// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dbproxy"
	"github.com/heliopsy/scrim/internal/natsconn"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// scrimConfigStore names the value source of scrim's own credentials.
const scrimConfigStore = "scrim-config"

// credFileMax bounds a credential file scrim reads for the redaction set.
const credFileMax = 64 << 10

// credFilePoll is how often the credential files are checked for a new
// value (a kubelet-rotated service account token, a reissued NATS
// credentials file) when nothing else rebuilds the snapshot.
var credFilePoll = 30 * time.Second

// scrimCredentials puts the credentials scrim holds for itself in the
// redaction set (specs/secret-stores "Scrim's own credentials are never
// exposed"): every resolved secret-ref setting and collection secret field
// of the running configuration (admin and metrics tokens, notifier, audit
// sink, Valkey, NATS and PostgreSQL credentials, signing keys, the CA key,
// placeholder keys, store credentials), the password inside
// state.postgres.dsn and each key of a PEM bundle on their own, and the
// credential files scrim's clients read themselves (nats.credentials-file,
// identity.kubernetes.token-file). They carry no reference: redacted, never
// injected. Database passwords have their own source (databasePasswords).
//
// The values follow the configuration: a reload that rotates a setting
// replaces its value. Credential files are read again when they change,
// and the value they held before stays redacted until the next change.
type scrimCredentials struct {
	cfg func() *config.Config

	mu    sync.Mutex
	files map[string]*credFile
}

type credFile struct {
	mod     time.Time
	size    int64
	cur     []secret.Value
	retired []secret.Value
}

func newScrimCredentials(cfg func() *config.Config) *scrimCredentials {
	return &scrimCredentials{cfg: cfg, files: map[string]*credFile{}}
}

func (*scrimCredentials) Store() string { return scrimConfigStore }

// EachValue implements ValueSource.
func (s *scrimCredentials) EachValue(fn func(refresh.Source, secret.Value)) {
	cfg := s.cfg()
	if cfg == nil {
		return
	}
	cfg.EachSecret(func(key string, v secret.Value) {
		if strings.HasPrefix(key, dbproxy.CollectionKey+".") {
			return
		}
		fn(refresh.Source{}, v)
		for _, part := range derivedParts(key, v) {
			fn(refresh.Source{}, part)
			part.Wipe()
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range credFiles(cfg) {
		cf := s.readLocked(f)
		if cf == nil {
			continue
		}
		for _, v := range cf.cur {
			fn(refresh.Source{}, v)
		}
		for _, v := range cf.retired {
			fn(refresh.Source{}, v)
		}
	}
}

// changed reports whether a credential file differs from what the
// redaction set holds.
func (s *scrimCredentials) changed() bool {
	cfg := s.cfg()
	if cfg == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range credFiles(cfg) {
		cf := s.files[f.path]
		st, err := os.Stat(f.path)
		switch {
		case err != nil:
			if cf != nil && len(cf.cur) > 0 {
				return true
			}
		case cf == nil || !st.ModTime().Equal(cf.mod) || st.Size() != cf.size:
			return true
		}
	}
	return false
}

// watch triggers a snapshot whenever a credential file changes, until ctx
// ends.
func (s *scrimCredentials) watch(ctx context.Context, trigger func()) {
	t := time.NewTicker(credFilePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.changed() {
				trigger()
			}
		}
	}
}

func (s *scrimCredentials) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, cf := range s.files {
		wipeAll(cf.cur)
		wipeAll(cf.retired)
		delete(s.files, p)
	}
}

// credFileSpec is a credential file and how its values are found in it.
type credFileSpec struct {
	path  string
	parse func([]byte) [][]byte
}

// credFiles are the credential files the configuration has scrim's clients
// read: NATS decorated credentials (a user JWT and an NKey seed) and the
// service account token Kubernetes identity authenticates TokenReview with.
func credFiles(cfg *config.Config) []credFileSpec {
	var out []credFileSpec
	if p := natsconn.CredentialsFile.Get(cfg); p != "" {
		out = append(out, credFileSpec{path: p, parse: blockBodies})
	}
	if agentapi.KubeEnabled.Get(cfg) {
		if p := agentapi.KubeTokenFile.Get(cfg); p != "" {
			out = append(out, credFileSpec{path: p, parse: func(b []byte) [][]byte { return [][]byte{bytes.TrimSpace(b)} }})
		}
	}
	return out
}

// readLocked returns f's values, reading the file again when it changed.
// The values it held before stay as retired until the next change; a file
// that cannot be read keeps what was read last.
func (s *scrimCredentials) readLocked(f credFileSpec) *credFile {
	cf := s.files[f.path]
	st, err := os.Stat(f.path)
	if err != nil || (cf != nil && st.ModTime().Equal(cf.mod) && st.Size() == cf.size) {
		return cf
	}
	b, err := readCredFile(f.path)
	if err != nil {
		return cf
	}
	defer secret.WipeBytes(b)
	var vals []secret.Value
	for _, part := range f.parse(b) {
		if len(part) > 0 {
			vals = append(vals, secret.New(part))
		}
	}
	if cf == nil {
		cf = &credFile{}
		s.files[f.path] = cf
	}
	wipeAll(cf.retired)
	cf.retired, cf.cur = cf.cur, vals
	cf.mod, cf.size = st.ModTime(), st.Size()
	return cf
}

func readCredFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, credFileMax))
}

func wipeAll(vs []secret.Value) {
	for _, v := range vs {
		v.Wipe()
	}
}

// derivedParts are the parts of a configured credential that are
// credentials on their own: the password of state.postgres.dsn, and each
// block of a PEM bundle holding more than one. The caller wipes them.
func derivedParts(key string, v secret.Value) []secret.Value {
	var out []secret.Value
	_ = v.Expose(func(b []byte) error {
		if key == postgres.DSNSetting.Name() {
			for _, p := range dsnPasswords(b) {
				out = append(out, secret.Adopt(p))
			}
			return nil
		}
		if blocks := pemBlocks(b); len(blocks) > 1 {
			for _, bl := range blocks {
				out = append(out, secret.New(bl.whole))
			}
		}
		return nil
	})
	return out
}

type pemBlock struct{ whole, body []byte }

// pemBlocks finds the armoured blocks of b: from a "-----BEGIN" line to the
// end of its "-----END" line, and the text between those lines. NATS
// decorated credentials use the same armour with extra dashes.
func pemBlocks(b []byte) []pemBlock {
	var out []pemBlock
	for {
		i := bytes.Index(b, []byte("-----BEGIN "))
		if i < 0 {
			return out
		}
		for i > 0 && b[i-1] == '-' {
			i--
		}
		nl := bytes.IndexByte(b[i:], '\n')
		if nl < 0 {
			return out
		}
		bodyStart := i + nl + 1
		e := bytes.Index(b[bodyStart:], []byte("-----END "))
		if e < 0 {
			return out
		}
		e += bodyStart
		lineStart := bytes.LastIndexByte(b[:e], '\n') + 1
		lineStart = max(lineStart, bodyStart)
		end := len(b)
		if n := bytes.IndexByte(b[e:], '\n'); n >= 0 {
			end = e + n
		}
		out = append(out, pemBlock{whole: bytes.TrimSpace(b[i:end]), body: bytes.TrimSpace(b[bodyStart:lineStart])})
		b = b[end:]
	}
}

// blockBodies returns the body of every armoured block in b.
func blockBodies(b []byte) [][]byte {
	var out [][]byte
	for _, bl := range pemBlocks(b) {
		out = append(out, bl.body)
	}
	return out
}

// dsnPasswords returns the password of a PostgreSQL connection string, in
// URL form (postgres://user:password@host/db) or keyword form
// (password=secret, password='with spaces'): as written, and decoded when
// percent-encoding or quoting changes it. The slices are copies; the caller
// wipes them.
func dsnPasswords(b []byte) [][]byte {
	var raw []byte
	var decoded []byte
	if rest, ok := cutScheme(b); ok {
		auth := rest
		if i := bytes.IndexAny(auth, "/?#"); i >= 0 {
			auth = auth[:i]
		}
		at := bytes.LastIndexByte(auth, '@')
		if at < 0 {
			return nil
		}
		_, pw, ok := bytes.Cut(auth[:at], []byte(":"))
		if !ok {
			return nil
		}
		raw, decoded = pw, percentDecode(pw)
	} else {
		raw, decoded = keywordPassword(b)
	}
	if len(raw) == 0 {
		secret.WipeBytes(decoded)
		return nil
	}
	out := [][]byte{bytes.Clone(raw)}
	if len(decoded) > 0 && !bytes.Equal(decoded, raw) {
		out = append(out, decoded)
	} else {
		secret.WipeBytes(decoded)
	}
	return out
}

func cutScheme(b []byte) ([]byte, bool) {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if len(b) >= len(p) && strings.EqualFold(string(b[:len(p)]), p) {
			return b[len(p):], true
		}
	}
	return nil, false
}

// percentDecode decodes %XX escapes into a new slice; nil when b has a
// malformed escape.
func percentDecode(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '%' {
			out = append(out, b[i])
			continue
		}
		if i+2 >= len(b) {
			secret.WipeBytes(out)
			return nil
		}
		hi, ok1 := unhex(b[i+1])
		lo, ok2 := unhex(b[i+2])
		if !ok1 || !ok2 {
			secret.WipeBytes(out)
			return nil
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// keywordPassword finds password=... in a keyword/value connection string
// and returns the value as written (without surrounding quotes) and with
// its backslash escapes resolved, in a new slice.
func keywordPassword(b []byte) (raw, decoded []byte) {
	i := 0
	space := func() {
		for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
			i++
		}
	}
	for i < len(b) {
		space()
		ks := i
		for i < len(b) && b[i] != '=' && b[i] != ' ' && b[i] != '\t' {
			i++
		}
		key := b[ks:i]
		space()
		if i >= len(b) || b[i] != '=' {
			return nil, nil
		}
		i++
		space()
		quoted := i < len(b) && b[i] == '\''
		if quoted {
			i++
		}
		vs := i
		var val []byte
		for i < len(b) {
			c := b[i]
			if c == '\\' && i+1 < len(b) {
				val = append(val, b[i+1])
				i += 2
				continue
			}
			if (quoted && c == '\'') || (!quoted && (c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
				break
			}
			val = append(val, c)
			i++
		}
		ve := i
		if quoted && i < len(b) {
			i++
		}
		if string(key) == "password" {
			return b[vs:ve], val
		}
		secret.WipeBytes(val)
	}
	return nil, nil
}
