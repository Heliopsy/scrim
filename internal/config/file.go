// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

// APIVersion is the config file format this release writes and documents.
const APIVersion = "scrim.dev/v1"

// FileKind is the `kind` every config file declares.
const FileKind = "Config"

// SupportedAPIVersions lists every apiVersion this release reads.
var SupportedAPIVersions = []string{APIVersion}

// Reserved top-level file keys that are not settings.
const (
	keyAPIVersion = "apiVersion"
	keyKind       = "kind"
	keyInclude    = "include"
)

const (
	maxConfigFile    = 4 << 20
	maxIncludeDepth  = 16
	maxIncludedFiles = 256
)

// FileSet is the merged content of the config files: the top-level files,
// then, for each file, its includes in the order listed (depth first). A
// value from a later file overrides an earlier one; map settings merge key
// by key.
type FileSet struct {
	// Files are every file read, in the order they were applied.
	Files []string
	// WatchDirs are the directories whose changes can change the result:
	// the directories of every file read, of every glob and every included
	// directory.
	WatchDirs []string
	// Raws are the setting values found, in apply order.
	Raws []Raw
	// Unknown are keys that name no setting.
	Unknown []*Problem

	colRaws []colRaw

	reg      *Registry
	stack    []string
	problems []error
	watch    map[string]bool
}

// Layer returns the file values as a [Layer].
func (fs *FileSet) Layer() Layer {
	return LayerFunc(func(*Registry) ([]Raw, error) { return fs.Raws, nil })
}

// LoadFiles reads and merges paths and everything they include. It returns
// every problem found, joined; unknown keys are reported separately in
// [FileSet.Unknown] since strictness is a setting.
func LoadFiles(r *Registry, paths []string) (*FileSet, error) {
	fs := &FileSet{reg: r, watch: map[string]bool{}}
	for _, p := range paths {
		fs.load(p, Source{})
	}
	return fs, errors.Join(fs.problems...)
}

func (fs *FileSet) problem(src Source, format string, args ...any) {
	fs.problems = append(fs.problems, &Problem{Source: src, Err: fmt.Errorf(format, args...)})
}

func (fs *FileSet) addWatch(dir string) {
	if !fs.watch[dir] {
		fs.watch[dir] = true
		fs.WatchDirs = append(fs.WatchDirs, dir)
	}
}

// load applies one file. from is the include line that named it, for errors.
func (fs *FileSet) load(path string, from Source) {
	abs, err := filepath.Abs(path)
	if err != nil {
		fs.problem(from, "config file %s: %v", path, err)
		return
	}
	fs.addWatch(filepath.Dir(abs))
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	if slices.Contains(fs.stack, real) {
		fs.problem(from, "include cycle: %s -> %s", strings.Join(fs.stack, " -> "), real)
		return
	}
	if len(fs.stack) >= maxIncludeDepth {
		fs.problem(from, "config file %s: includes nested deeper than %d", abs, maxIncludeDepth)
		return
	}
	if len(fs.Files) >= maxIncludedFiles {
		fs.problem(from, "config file %s: more than %d files in total", abs, maxIncludedFiles)
		return
	}
	data, err := readConfigFile(abs)
	if err != nil {
		fs.problem(from, "config file %s: %v", abs, err)
		return
	}
	fs.Files = append(fs.Files, abs)
	fs.stack = append(fs.stack, real)
	defer func() { fs.stack = fs.stack[:len(fs.stack)-1] }()

	root, err := parseDocument(abs, data)
	if err != nil {
		fs.problems = append(fs.problems, err)
		return
	}
	var include *yaml.Node
	seen := map[string]int{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case keyAPIVersion, keyKind:
			continue
		case keyInclude:
			include = v
			continue
		}
		fs.walk(abs, nil, k, v, seen)
	}
	if include != nil {
		fs.includes(abs, include)
	}
}

func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return nil, pe.Err
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigFile {
		return nil, fmt.Errorf("larger than %d bytes", maxConfigFile)
	}
	return data, nil
}

// parseDocument parses one YAML document and checks apiVersion and kind.
func parseDocument(path string, data []byte) (*yaml.Node, error) {
	src := fileSource(path, 0)
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &Problem{Source: src, Err: fmt.Errorf("invalid YAML: %w", err)}
	}
	supported := strings.Join(SupportedAPIVersions, ", ")
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, &Problem{Source: src, Err: fmt.Errorf("empty file: declare apiVersion (supported: %s) and kind: %s", supported, FileKind)}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, &Problem{Source: fileSource(path, root.Line), Err: errors.New("the document must be a mapping")}
	}
	var apiVersion, kind *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case keyAPIVersion:
			apiVersion = root.Content[i+1]
		case keyKind:
			kind = root.Content[i+1]
		}
	}
	switch {
	case apiVersion == nil:
		return nil, &Problem{Source: src, Err: fmt.Errorf("missing apiVersion (supported: %s)", supported)}
	case apiVersion.Kind != yaml.ScalarNode || !slices.Contains(SupportedAPIVersions, apiVersion.Value):
		return nil, &Problem{Source: fileSource(path, apiVersion.Line), Err: fmt.Errorf("apiVersion %q is not supported (supported: %s)", apiVersion.Value, supported)}
	case kind == nil:
		return nil, &Problem{Source: src, Err: fmt.Errorf("missing kind (expected %s)", FileKind)}
	case kind.Kind != yaml.ScalarNode || kind.Value != FileKind:
		return nil, &Problem{Source: fileSource(path, kind.Line), Err: fmt.Errorf("kind %q is not supported (expected %s)", kind.Value, FileKind)}
	}
	return root, nil
}

func fileSource(path string, line int) Source {
	if line <= 0 {
		return Source{Kind: SourceFile, Name: path}
	}
	return Source{Kind: SourceFile, Name: path + ":" + strconv.Itoa(line)}
}

// walk descends one mapping entry. A key may itself be dotted
// (`approvals.timeout: 60s`), so nested and flat spellings mix freely.
func (fs *FileSet) walk(path string, prefix []string, k, v *yaml.Node, seen map[string]int) {
	src := fileSource(path, k.Line)
	if k.Kind != yaml.ScalarNode || k.Value == "" {
		fs.problem(src, "keys must be non-empty strings")
		return
	}
	segs := append(slices.Clone(prefix), strings.Split(k.Value, ".")...)
	key := strings.Join(segs, ".")
	if slices.Contains(segs, "") {
		fs.problem(src, "key %q has an empty part", key)
		return
	}
	if v.Kind == yaml.AliasNode {
		v = v.Alias
	}

	if col, n := fs.reg.collectionAt(segs); col != nil {
		switch {
		case len(segs) == n:
			if v.Kind != yaml.MappingNode {
				fs.problems = append(fs.problems, &Problem{Key: key, Source: src, Err: errors.New("is a collection and needs a mapping of named instances")})
				return
			}
			for i := 0; i+1 < len(v.Content); i += 2 {
				nk := v.Content[i]
				fs.colWalk(path, col, nk.Value, nil, v.Content[i+1], nk.Line, seen)
			}
		default:
			fs.colWalk(path, col, segs[n], segs[n+1:], v, k.Line, seen)
		}
		return
	}

	if s, ok := fs.reg.Lookup(key); ok {
		if line, dup := seen[key]; dup {
			fs.problems = append(fs.problems, &Problem{Key: key, Source: src, Err: fmt.Errorf("set twice in this file (first on line %d)", line)})
			return
		}
		seen[key] = k.Line
		val, err := decodeValue(s, v)
		if err != nil {
			fs.problems = append(fs.problems, &Problem{Key: key, Source: src, Err: err})
			return
		}
		fs.Raws = append(fs.Raws, Raw{Key: key, Value: val, Source: src, Merge: s.Kind == KindMap})
		return
	}

	// An entry of a map setting written as a dotted key:
	// `proxy.upstream.anthropic: http://...`.
	for i := len(segs) - 1; i > 0; i-- {
		s, ok := fs.reg.Lookup(strings.Join(segs[:i], "."))
		if !ok {
			continue
		}
		if s.Kind != KindMap {
			break
		}
		if v.Kind != yaml.ScalarNode || v.Tag == "!!null" {
			fs.problems = append(fs.problems, &Problem{Key: s.Key, Source: src, Err: fmt.Errorf("map entry %q must be a string", strings.Join(segs[i:], "."))})
			return
		}
		fs.Raws = append(fs.Raws, Raw{
			Key: s.Key, Value: map[string]any{strings.Join(segs[i:], "."): v.Value},
			Source: src, Merge: true,
		})
		return
	}

	if fs.reg.isSection(key) {
		if v.Kind != yaml.MappingNode {
			fs.problems = append(fs.problems, &Problem{Key: key, Source: src, Err: errors.New("is a section and needs a mapping of settings")})
			return
		}
		for i := 0; i+1 < len(v.Content); i += 2 {
			fs.walk(path, segs, v.Content[i], v.Content[i+1], seen)
		}
		return
	}
	if v.Kind == yaml.MappingNode && len(v.Content) > 0 {
		// Report the leaves, so `aprovals: {timeout: 60s}` suggests
		// approvals.timeout rather than nothing.
		for i := 0; i+1 < len(v.Content); i += 2 {
			fs.walk(path, segs, v.Content[i], v.Content[i+1], seen)
		}
		return
	}
	fs.Unknown = append(fs.Unknown, unknownKeyProblem(fs.reg, key, src))
}

// decodeValue turns a YAML node into a raw value for [Parse].
func decodeValue(s *Setting, v *yaml.Node) (any, error) {
	if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
		return nil, errors.New("has no value; remove the key to use the default")
	}
	switch s.Kind {
	case KindList:
		if v.Kind != yaml.SequenceNode {
			return nil, errors.New("expected a list")
		}
		out := make([]any, 0, len(v.Content))
		for _, item := range v.Content {
			if item.Kind != yaml.ScalarNode || item.Tag == "!!null" {
				return nil, fmt.Errorf("line %d: list items must be strings", item.Line)
			}
			out = append(out, item.Value)
		}
		return out, nil
	case KindMap:
		if v.Kind != yaml.MappingNode {
			return nil, errors.New("expected a mapping of strings")
		}
		out := make(map[string]any, len(v.Content)/2)
		for i := 0; i+1 < len(v.Content); i += 2 {
			mk, mv := v.Content[i], v.Content[i+1]
			if mk.Kind != yaml.ScalarNode || mv.Kind != yaml.ScalarNode || mv.Tag == "!!null" {
				return nil, fmt.Errorf("line %d: map keys and values must be strings", mk.Line)
			}
			out[mk.Value] = mv.Value
		}
		return out, nil
	}
	if v.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("expected a %s value, got a %s", s.Kind, nodeKindName(v))
	}
	switch s.Kind {
	case KindString, KindSecretRef, KindDuration:
		if v.Tag != "!!str" {
			return nil, fmt.Errorf("expected a %s written as a string, got %s; quote it", s.Kind, strings.TrimPrefix(v.Tag, "!!"))
		}
		return v.Value, nil
	default:
		var out any
		if err := v.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func nodeKindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "list"
	}
	return "value"
}

// includes applies the include list of the file at path.
//
// Each entry is a path, a glob or a directory, relative to the including
// file. A plain path must exist unless written as {path: ..., optional:
// true}; a glob may match nothing; a directory contributes its *.yaml and
// *.yml files. Matches apply in lexical order.
func (fs *FileSet) includes(path string, n *yaml.Node) {
	items := []*yaml.Node{n}
	if n.Kind == yaml.SequenceNode {
		items = n.Content
	}
	base := filepath.Dir(path)
	for _, item := range items {
		src := fileSource(path, item.Line)
		var (
			target   string
			optional bool
		)
		switch item.Kind {
		case yaml.ScalarNode:
			target = item.Value
		case yaml.MappingNode:
			var spec struct {
				Path     string `yaml:"path"`
				Optional bool   `yaml:"optional"`
			}
			if err := item.Decode(&spec); err != nil {
				fs.problem(src, "include: %v", err)
				continue
			}
			for i := 0; i < len(item.Content); i += 2 {
				if k := item.Content[i].Value; k != "path" && k != "optional" {
					fs.problem(src, "include: unknown field %q (fields: path, optional)", k)
				}
			}
			target, optional = spec.Path, spec.Optional
		default:
			fs.problem(src, "include: entries must be paths or {path, optional}")
			continue
		}
		if target == "" {
			fs.problem(src, "include: empty path")
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(base, target)
		}
		fs.includeTarget(target, optional, src)
	}
}

func (fs *FileSet) includeTarget(target string, optional bool, src Source) {
	if strings.ContainsAny(target, "*?[") {
		matches, err := filepath.Glob(target)
		if err != nil {
			fs.problem(src, "include %s: %v", target, err)
			return
		}
		fs.addWatch(filepath.Dir(target))
		slices.Sort(matches)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && !fi.IsDir() {
				fs.load(m, src)
			}
		}
		return
	}
	fi, err := os.Stat(target)
	switch {
	case err != nil && optional && errors.Is(err, os.ErrNotExist):
		fs.addWatch(filepath.Dir(target))
		return
	case err != nil:
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		fs.problem(src, "include %s: %v", target, err)
		return
	case fi.IsDir():
		fs.addWatch(target)
		entries, err := os.ReadDir(target)
		if err != nil {
			fs.problem(src, "include %s: %v", target, err)
			return
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, ".") || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
				continue
			}
			fs.load(filepath.Join(target, name), src)
		}
	default:
		fs.load(target, src)
	}
}

// isSection reports whether key is a proper prefix of a registered key.
func (r *Registry) isSection(key string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for k := range r.settings {
		if strings.HasPrefix(k, key+".") {
			return true
		}
	}
	for k := range r.collections {
		if strings.HasPrefix(k, key+".") {
			return true
		}
	}
	return false
}
