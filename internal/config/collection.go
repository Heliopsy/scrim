// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

// CollectionSpec declares a collection: a section holding any number of
// named instances whose fields the owning package defines, such as the
// secret store instances under `stores`:
//
//	stores:
//	  bao-prod:
//	    kind: openbao
//	    address: https://bao.example.com
//	    token: file:/run/secrets/bao-token
//
// The instance name is free (lower-case words with dashes); each field is
// addressed by the dotted key `stores.bao-prod.token`, from the file and from
// the environment (SCRIM_STORES_BAO_PROD_TOKEN, see [Build]).
type CollectionSpec struct {
	// Key is the dotted key of the collection, `stores`.
	Key string
	// Description is shown in the generated documentation.
	Description string
	// SecretFields names the fields that hold secret references in every
	// instance (`token`, `client-secret`). They are resolved at load like
	// secret-ref settings, masked in every output, and a literal is warned
	// about or, with RequireReference, rejected.
	SecretFields []string
	// RequireReference rejects literal values in SecretFields.
	RequireReference bool
	// RequiredFields must be present in every instance (`kind`).
	RequiredFields []string
	// RestartRequired marks a collection a hot reload cannot change.
	RestartRequired bool
	// Validate, if set, checks one instance. It must not include secret
	// values in its errors.
	Validate func(Instance) error
	// ValidateAll, if set, checks the instances together, for rules between
	// them. It runs after Validate and before any secret field is resolved.
	// It must not include secret values in its errors.
	ValidateAll func([]Instance) error
	// FieldSchemas are JSON schemas of further instance fields, for the
	// generated schema.
	FieldSchemas map[string]map[string]any
}

// Collection is a handle to a registered collection.
type Collection struct{ spec *CollectionSpec }

// Key returns the collection's dotted key.
func (k Collection) Key() string { return k.spec.Key }

// Instance is one named instance of a collection. Fields holds the decoded
// YAML tree (string, bool, int, float64, []any, map[string]any); secret
// fields hold their reference string, resolved values are read with
// [Config.SecretAt].
type Instance struct {
	Name   string
	Fields map[string]any
	// Sources maps each leaf field path (`tls.ca`) to where it came from.
	Sources map[string]Source
}

// Key returns the dotted key of a field of the instance.
func (i Instance) Key(collection, field string) string {
	return collection + "." + i.Name + "." + field
}

// String returns a string field, or "" when it is missing or not a string.
func (i Instance) String(field string) string {
	s, _ := lookupPath(i.Fields, strings.Split(field, ".")).(string)
	return s
}

// Field returns the value at a dotted field path.
func (i Instance) Field(path string) (any, bool) {
	v := lookupPath(i.Fields, strings.Split(path, "."))
	return v, v != nil
}

var instanceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// RegisterCollection declares a collection in [Default].
func RegisterCollection(spec CollectionSpec) Collection {
	c, err := RegisterCollectionIn(Default, spec)
	if err != nil {
		panic(err)
	}
	return c
}

// RegisterCollectionIn declares a collection in r.
func RegisterCollectionIn(r *Registry, spec CollectionSpec) (Collection, error) {
	if !keyPattern.MatchString(spec.Key) {
		return Collection{}, fmt.Errorf("config: invalid collection key %q", spec.Key)
	}
	if strings.TrimSpace(spec.Description) == "" {
		return Collection{}, fmt.Errorf("config: collection %s has no description", spec.Key)
	}
	for _, f := range append(slices.Clone(spec.SecretFields), spec.RequiredFields...) {
		if !keyPattern.MatchString(f) || strings.Contains(f, ".") {
			return Collection{}, fmt.Errorf("config: collection %s: invalid field name %q", spec.Key, f)
		}
	}
	s := spec
	s.Description = strings.TrimSpace(spec.Description)
	s.SecretFields = slices.Clone(spec.SecretFields)
	s.RequiredFields = slices.Clone(spec.RequiredFields)

	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.settings {
		if k == s.Key || strings.HasPrefix(k, s.Key+".") || strings.HasPrefix(s.Key, k+".") {
			return Collection{}, fmt.Errorf("config: collection %s conflicts with setting %s", s.Key, k)
		}
	}
	if col := r.collisionWithCollection(s.Key); col != "" {
		return Collection{}, fmt.Errorf("config: collection %s conflicts with collection %s", s.Key, col)
	}
	if r.collections == nil {
		r.collections = map[string]*CollectionSpec{}
	}
	r.collections[s.Key] = &s
	return Collection{spec: &s}, nil
}

// collisionWithCollection returns a collection whose key equals key or is
// a prefix of it, or that key is a prefix of. The caller holds r.mu.
func (r *Registry) collisionWithCollection(key string) string {
	for k := range r.collections {
		if k == key || strings.HasPrefix(key, k+".") || strings.HasPrefix(k, key+".") {
			return k
		}
	}
	return ""
}

// Collections returns every registered collection sorted by key.
func (r *Registry) Collections() []*CollectionSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := slices.Collect(maps.Values(r.collections))
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// collectionAt returns the collection whose key is a prefix of segs, and the
// number of segments the key takes.
func (r *Registry) collectionAt(segs []string) (*CollectionSpec, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 1; i <= len(segs); i++ {
		if c, ok := r.collections[strings.Join(segs[:i], ".")]; ok {
			return c, i
		}
	}
	return nil, 0
}

// colRaw is one value for a collection: a field (or, with an empty path, the
// existence of an instance).
type colRaw struct {
	col    *CollectionSpec
	name   string
	path   []string
	value  any
	source Source
}

func (cr colRaw) key() string {
	return strings.Join(append([]string{cr.col.Key, cr.name}, cr.path...), ".")
}

// colWalk records the values below an instance from YAML.
func (fs *FileSet) colWalk(file string, col *CollectionSpec, name string, path []string, v *yaml.Node, line int, seen map[string]int) {
	src := fileSource(file, line)
	if !instanceNamePattern.MatchString(name) {
		fs.problems = append(fs.problems, &Problem{Key: col.Key + "." + name, Source: src,
			Err: fmt.Errorf("instance name %q must be lower-case words separated by dashes", name)})
		return
	}
	if v.Kind == yaml.AliasNode {
		v = v.Alias
	}
	if v.Kind == yaml.MappingNode {
		if len(v.Content) == 0 {
			fs.colRaws = append(fs.colRaws, colRaw{col: col, name: name, path: path, value: map[string]any{}, source: src})
			return
		}
		for i := 0; i+1 < len(v.Content); i += 2 {
			k := v.Content[i]
			parts := strings.Split(k.Value, ".")
			if k.Kind != yaml.ScalarNode || slices.Contains(parts, "") {
				fs.problem(fileSource(file, k.Line), "keys must be non-empty strings")
				continue
			}
			fs.colWalk(file, col, name, append(slices.Clone(path), parts...), v.Content[i+1], k.Line, seen)
		}
		return
	}
	cr := colRaw{col: col, name: name, path: path, source: src}
	if len(path) == 0 {
		fs.problems = append(fs.problems, &Problem{Key: cr.key(), Source: src, Err: errors.New("an instance must be a mapping of fields")})
		return
	}
	if first, dup := seen[cr.key()]; dup {
		fs.problems = append(fs.problems, &Problem{Key: cr.key(), Source: src, Err: fmt.Errorf("set twice in this file (first on line %d)", first)})
		return
	}
	seen[cr.key()] = line
	if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
		fs.problems = append(fs.problems, &Problem{Key: cr.key(), Source: src, Err: errors.New("has no value; remove the key instead")})
		return
	}
	var val any
	if err := v.Decode(&val); err != nil {
		fs.problems = append(fs.problems, &Problem{Key: cr.key(), Source: src, Err: err})
		return
	}
	cr.value = normalizeTree(val)
	fs.colRaws = append(fs.colRaws, cr)
}

// normalizeTree converts decoded YAML into JSON-like types.
func normalizeTree(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = normalizeTree(x)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = normalizeTree(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalizeTree(x)
		}
		return out
	case int64:
		return int(t)
	case uint64:
		return int(t) // #nosec G115 -- YAML integers beyond int64 fail to decode before this
	}
	return v
}

// colState is the merged content of one collection.
type colState map[string]*Instance

func (st colState) apply(cr colRaw) {
	inst := st[cr.name]
	if inst == nil {
		inst = &Instance{Name: cr.name, Fields: map[string]any{}, Sources: map[string]Source{}}
		st[cr.name] = inst
	}
	inst.set(cr.path, cr.value, cr.source)
}

// set writes v at path: maps merge key by key, anything else replaces.
func (i *Instance) set(path []string, v any, src Source) {
	if m, ok := v.(map[string]any); ok {
		if len(m) == 0 && len(path) > 0 {
			i.setLeaf(path, map[string]any{}, src)
			return
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			i.set(append(slices.Clone(path), k), m[k], src)
		}
		return
	}
	i.setLeaf(path, v, src)
}

func (i *Instance) setLeaf(path []string, v any, src Source) {
	if len(path) == 0 {
		return
	}
	node := i.Fields
	for n, seg := range path[:len(path)-1] {
		next, ok := node[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			node[seg] = next
			delete(i.Sources, strings.Join(path[:n+1], "."))
		}
		node = next
	}
	node[path[len(path)-1]] = v
	key := strings.Join(path, ".")
	for p := range i.Sources {
		if strings.HasPrefix(p, key+".") {
			delete(i.Sources, p)
		}
	}
	i.Sources[key] = src
}

func lookupPath(m map[string]any, path []string) any {
	var cur any = m
	for _, seg := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[seg]
	}
	return cur
}

// leaves returns every leaf field path of the instance, sorted.
func (i *Instance) leaves() []string { return slices.Sorted(maps.Keys(i.Sources)) }

func (i *Instance) clone() *Instance {
	n := &Instance{Name: i.Name, Fields: deepClone(i.Fields).(map[string]any), Sources: maps.Clone(i.Sources)}
	return n
}

func deepClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepClone(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepClone(x)
		}
		return out
	}
	return v
}

// applyCollectionEnv applies the environment to the collections: a variable
// named for the whole collection (SCRIM_STORES) holds a JSON object of
// instances and replaces the collection; a variable named for a field
// already present (from a file or the whole-collection variable) overrides
// it with the same type; a variable that extends the name of a known
// instance adds a string field to it. A variable that matches a collection
// prefix but none of these is reported as a warning, since the instance
// name cannot be recovered from it.
func applyCollectionEnv(r *Registry, states map[string]colState, environ []string) ([]Warning, []error) {
	env := environMap(environ)
	names := slices.Sorted(maps.Keys(env))
	var warns []Warning
	var errs []error
	for _, col := range r.Collections() {
		st := states[col.Key]
		whole := EnvVar(col.Key)
		if raw, ok := env[whole]; ok {
			src := Source{Kind: SourceEnv, Name: whole}
			var tree map[string]any
			if err := json.Unmarshal([]byte(raw), &tree); err != nil {
				errs = append(errs, &Problem{Key: col.Key, Source: src, Err: errors.New("expected a JSON object of instances")})
			} else {
				st = colState{}
				for _, name := range slices.Sorted(maps.Keys(tree)) {
					body, ok := tree[name].(map[string]any)
					if !ok || !instanceNamePattern.MatchString(name) {
						errs = append(errs, &Problem{Key: col.Key + "." + name, Source: src, Err: errors.New("each instance must be a JSON object under a lower-case dashed name")})
						continue
					}
					st.apply(colRaw{col: col, name: name, value: normalizeJSON(body).(map[string]any), source: src})
				}
				states[col.Key] = st
			}
		}
		prefix := whole + "_"
		for _, name := range names {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if _, isSetting := r.LookupEnv(name); isSetting {
				continue
			}
			src := Source{Kind: SourceEnv, Name: name}
			inst, path := matchCollectionEnv(col, st, name)
			if inst == nil {
				warns = append(warns, Warning{Key: col.Key, Source: src, Message: fmt.Sprintf(
					"matches no configured %s instance; declare the instance in a file or set %s as JSON", col.Key, whole)})
				continue
			}
			v, err := typedLike(lookupPath(inst.Fields, path), env[name])
			if err != nil {
				errs = append(errs, &Problem{Key: col.Key + "." + inst.Name + "." + strings.Join(path, "."), Source: src, Err: err})
				continue
			}
			inst.setLeaf(path, v, src)
		}
	}
	return warns, errs
}

// matchCollectionEnv finds the instance and field path a variable names:
// first an existing leaf with exactly that variable name, then the longest
// instance whose variable is a prefix, with the rest as one field name.
func matchCollectionEnv(col *CollectionSpec, st colState, name string) (*Instance, []string) {
	var best *Instance
	for _, iname := range slices.Sorted(maps.Keys(st)) {
		inst := st[iname]
		for _, leaf := range inst.leaves() {
			if EnvVar(col.Key+"."+iname+"."+leaf) == name {
				return inst, strings.Split(leaf, ".")
			}
		}
		if p := EnvVar(col.Key+"."+iname) + "_"; strings.HasPrefix(name, p) && len(name) > len(p) {
			if best == nil || len(iname) > len(best.Name) {
				best = inst
			}
		}
	}
	if best == nil {
		return nil, nil
	}
	rest := name[len(EnvVar(col.Key+"."+best.Name))+1:]
	return best, []string{strings.ReplaceAll(strings.ToLower(rest), "_", "-")}
}

// typedLike parses an environment string to the type of the value it
// replaces: bool, int and float fields stay typed, lists and maps take JSON.
func typedLike(prev any, raw string) (any, error) {
	switch prev.(type) {
	case bool:
		return strconv.ParseBool(raw)
	case int:
		return strconv.Atoi(raw)
	case float64:
		return strconv.ParseFloat(raw, 64)
	case []any, map[string]any:
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("expected JSON: %w", err)
		}
		if reflect.TypeOf(v) != reflect.TypeOf(prev) {
			return nil, fmt.Errorf("expected a JSON %T", prev)
		}
		return normalizeJSON(v), nil
	}
	return raw, nil
}

// normalizeJSON turns whole-number JSON floats into ints, matching YAML.
func normalizeJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeJSON(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeJSON(x)
		}
		return t
	case float64:
		if t == float64(int(t)) {
			return int(t)
		}
	}
	return v
}

// Get returns the instances of the collection in c, sorted by name.
// The returned values are copies.
func (k Collection) Get(c *Config) []Instance {
	st := c.collections[k.spec.Key]
	out := make([]Instance, 0, len(st))
	for _, name := range slices.Sorted(maps.Keys(st)) {
		out = append(out, *st[name].clone())
	}
	return out
}

// checkCollections validates instances: required fields, the collection's
// Validate hook and the type of secret fields.
func (c *Config) checkCollections() []error {
	var errs []error
	for _, col := range c.reg.Collections() {
		st := c.collections[col.Key]
		for _, name := range slices.Sorted(maps.Keys(st)) {
			inst := st[name]
			instSrc := firstSource(inst)
			for _, f := range col.RequiredFields {
				if _, ok := inst.Fields[f]; !ok {
					errs = append(errs, &Problem{Key: inst.Key(col.Key, f), Source: instSrc, Err: errors.New("is required")})
				}
			}
			for _, f := range col.SecretFields {
				if v, ok := inst.Fields[f]; ok {
					if _, isStr := v.(string); !isStr {
						errs = append(errs, &Problem{Key: inst.Key(col.Key, f), Source: inst.Sources[f], Err: errors.New("expected a secret reference string")})
					}
				}
			}
			if col.Validate != nil {
				if err := col.Validate(*inst.clone()); err != nil {
					errs = append(errs, &Problem{Key: col.Key + "." + name, Source: instSrc, Err: err})
				}
			}
		}
		if col.ValidateAll != nil && len(st) > 0 {
			all := make([]Instance, 0, len(st))
			for _, name := range slices.Sorted(maps.Keys(st)) {
				all = append(all, *st[name].clone())
			}
			if err := col.ValidateAll(all); err != nil {
				errs = append(errs, &Problem{Key: col.Key, Err: err})
			}
		}
	}
	return errs
}

func firstSource(inst *Instance) Source {
	leaves := inst.leaves()
	if len(leaves) == 0 {
		return Source{}
	}
	return inst.Sources[leaves[0]]
}

// collectionSecrets lists the secret fields of every instance as full keys
// with their reference and source.
func (c *Config) collectionSecrets() []secretField {
	var out []secretField
	for _, col := range c.reg.Collections() {
		st := c.collections[col.Key]
		for _, name := range slices.Sorted(maps.Keys(st)) {
			inst := st[name]
			for _, f := range col.SecretFields {
				if s, ok := inst.Fields[f].(string); ok {
					out = append(out, secretField{key: inst.Key(col.Key, f), ref: SecretRef(s), source: inst.Sources[f], require: col.RequireReference, restart: col.RestartRequired})
				}
			}
		}
	}
	return out
}

type secretField struct {
	key     string
	ref     SecretRef
	source  Source
	require bool
	restart bool
}

// isSecretField reports whether a leaf of a collection is a secret field.
func isSecretField(col *CollectionSpec, path string) bool {
	return slices.Contains(col.SecretFields, path)
}
