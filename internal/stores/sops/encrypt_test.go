// SPDX-License-Identifier: AGPL-3.0-only

package sops

// A test-only SOPS encryptor, so fixtures are generated at test time with
// throwaway age keys and no test depends on the sops binary. Its output is
// checked against the real sops binary in TestSopsBinaryDecryptsOurFiles.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v4"
)

// TB is the testing subset the encryptor needs (storetest.TB fits).
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// encOptions tune a generated file.
type encOptions struct {
	recipients []*age.X25519Recipient
	// rule is one sops encryption rule ("unencrypted_suffix",
	// "encrypted_regex", ...) and its value; none means the default
	// unencrypted suffix.
	rule, ruleValue string
	macOnly         bool
	// tamper, when set, rewrites the plaintext MAC before it is encrypted.
	tamperMAC bool
	// noMAC writes an empty MAC.
	noMAC bool
}

func sealValue(t TB, key []byte, plaintext []byte, additional, typ string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 32)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	iv := make([]byte, 32)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	out := gcm.Seal(nil, iv, plaintext, []byte(additional))
	data, tag := out[:len(out)-gcm.Overhead()], out[len(out)-gcm.Overhead():]
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(data), base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(tag), typ)
}

// encryptTree encrypts the string leaves of data in place the way sops does
// and returns the metadata tree. Non-string leaves must be unencrypted by
// the rule.
func encryptTree(t TB, data *node, o encOptions) *node {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	lastMod := time.Now().UTC().Truncate(time.Second)
	md, err := parseMetadata(metaTree(t, o, nil, lastMod, ""))
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	h := sha512.New()
	if o.macOnly {
		h.Write(macOnlyInit)
	}
	_ = walk(data, nil, "", func(n *node, path []string, _ string) error {
		enc := md.encrypted(path)
		if !enc || n.text == "" {
			if !o.macOnly || enc {
				h.Write([]byte(n.text))
			}
			return nil
		}
		if !n.str {
			t.Fatalf("test encryptor: only string leaves can be encrypted")
		}
		h.Write([]byte(n.text))
		n.text = sealValue(t, key, []byte(n.text), strings.Join(path, ":")+":", "str")
		return nil
	})
	mac := fmt.Sprintf("%X", h.Sum(nil))
	if o.tamperMAC {
		mac = strings.Repeat("0", len(mac))
	}
	encMAC := sealValue(t, key, []byte(mac), lastMod.Format(time.RFC3339), "str")
	if o.noMAC {
		encMAC = ""
	}
	return metaTree(t, o, key, lastMod, encMAC)
}

func metaTree(t TB, o encOptions, key []byte, lastMod time.Time, mac string) *node {
	t.Helper()
	leaf := func(s string) *node { return &node{kind: kindLeaf, str: true, text: s} }
	m := newMap()
	ages := &node{kind: kindList}
	for _, r := range o.recipients {
		enc := ""
		if key != nil {
			var buf bytes.Buffer
			aw := armor.NewWriter(&buf)
			w, err := age.Encrypt(aw, r)
			if err != nil {
				t.Fatalf("age: %v", err)
			}
			_, _ = w.Write(key)
			_ = w.Close()
			_ = aw.Close()
			enc = buf.String() + "\n"
		}
		item := newMap()
		item.set("recipient", leaf(r.String()))
		item.set("enc", leaf(enc))
		ages.items = append(ages.items, item)
	}
	m.set("age", ages)
	m.set("lastmodified", leaf(lastMod.Format(time.RFC3339)))
	m.set("mac", leaf(mac))
	if o.rule != "" {
		m.set(o.rule, leaf(o.ruleValue))
	}
	if o.macOnly {
		m.set("mac_only_encrypted", &node{kind: kindLeaf, text: "True"})
	}
	m.set("version", leaf("3.12.1"))
	return m
}

// render writes data and metadata as a SOPS file in format f.
func render(t TB, f Format, data, meta *node) []byte {
	t.Helper()
	switch f {
	case FormatYAML:
		root := toYAML(data)
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: metadataKey}, toYAML(meta))
		b, err := yaml.Marshal(root)
		if err != nil {
			t.Fatalf("yaml: %v", err)
		}
		return b
	case FormatJSON:
		all := newMap()
		all.keys = append(append(all.keys, data.keys...), metadataKey)
		all.vals = append(append(all.vals, data.vals...), meta)
		var b bytes.Buffer
		writeJSON(&b, all)
		return b.Bytes()
	case FormatDotenv:
		var b strings.Builder
		for i, k := range data.keys {
			b.WriteString(k + "=" + strings.ReplaceAll(data.vals[i].text, "\n", `\n`) + "\n")
		}
		for _, kv := range flatten(meta, "") {
			b.WriteString("sops_" + kv[0] + "=" + strings.ReplaceAll(kv[1], "\n", `\n`) + "\n")
		}
		return []byte(b.String())
	case FormatINI:
		var b strings.Builder
		for i, sec := range data.keys {
			b.WriteString("[" + sec + "]\n")
			s := data.vals[i]
			for j, k := range s.keys {
				b.WriteString(k + " = " + s.vals[j].text + "\n")
			}
			b.WriteString("\n")
		}
		b.WriteString("[sops]\n")
		for _, kv := range flatten(meta, "") {
			b.WriteString(kv[0] + " = " + strings.ReplaceAll(kv[1], "\n", `\n`) + "\n")
		}
		return []byte(b.String())
	}
	t.Fatalf("render: unknown format %s", f)
	return nil
}

func toYAML(n *node) *yaml.Node {
	switch n.kind {
	case kindMap:
		y := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for i, k := range n.keys {
			y.Content = append(y.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, toYAML(n.vals[i]))
		}
		return y
	case kindList:
		y := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, it := range n.items {
			y.Content = append(y.Content, toYAML(it))
		}
		return y
	case kindNull:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	}
	if n.str {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: n.text}
	}
	switch n.text {
	case "True":
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}
	case "False":
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}
	}
	tag := "!!int"
	if strings.ContainsAny(n.text, ".eE") {
		tag = "!!float"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: n.text}
}

func writeJSON(b *bytes.Buffer, n *node) {
	q := func(s string) {
		e, _ := json.Marshal(s)
		b.Write(e)
	}
	switch n.kind {
	case kindMap:
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			q(k)
			b.WriteByte(':')
			writeJSON(b, n.vals[i])
		}
		b.WriteByte('}')
	case kindList:
		b.WriteByte('[')
		for i, it := range n.items {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, it)
		}
		b.WriteByte(']')
	case kindNull:
		b.WriteString("null")
	default:
		switch {
		case n.str:
			q(n.text)
		case n.text == "True":
			b.WriteString("true")
		case n.text == "False":
			b.WriteString("false")
		default:
			b.WriteString(n.text)
		}
	}
}

// flatten is sops' metadata flattening for dotenv and ini.
func flatten(n *node, prefix string) [][2]string {
	var out [][2]string
	switch n.kind {
	case kindMap:
		for i, k := range n.keys {
			p := k
			if prefix != "" {
				p = prefix + flatMap + k
			}
			out = append(out, flatten(n.vals[i], p)...)
		}
	case kindList:
		for i, it := range n.items {
			out = append(out, flatten(it, fmt.Sprintf("%s%s%d", prefix, flatList, i))...)
		}
	default:
		text := n.text
		if !n.str {
			text = strings.ToLower(text)
		}
		out = append(out, [2]string{prefix, text})
	}
	return out
}

// flatDoc builds a flat document from fields, keys sorted.
func flatDoc(fields map[string]string) *node {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	n := newMap()
	for _, k := range keys {
		n.set(k, &node{kind: kindLeaf, str: true, text: fields[k]})
	}
	return n
}

// encryptFile generates a SOPS file in format f from data (modified in
// place).
func encryptFile(t TB, f Format, data *node, o encOptions) []byte {
	t.Helper()
	meta := encryptTree(t, data, o)
	return render(t, f, data, meta)
}
