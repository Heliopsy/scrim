package redact

// Redactor replaces every known secret variant in a raw JSON body with its placeholder.
type Redactor struct {
	eng   Engine
	owner []int32  // pattern -> secret
	ph    [][]byte // secret -> placeholder
	Pats  [][]byte
}

func NewRedactor(secrets [][]byte, key []byte, engine string) (*Redactor, error) {
	pats, owner := Patterns(secrets)
	eng, err := NewEngine(engine, pats)
	if err != nil {
		return nil, err
	}
	ph := make([][]byte, len(secrets))
	for i, s := range secrets {
		ph[i] = Placeholder(key, s)
	}
	return &Redactor{eng: eng, owner: owner, ph: ph, Pats: pats}, nil
}

func (r *Redactor) Engine() Engine { return r.eng }

// Redact returns the redacted body and the number of replacements.
// With no match it returns body itself (no copy). Otherwise it appends to dst[:0]
// (pass a pooled buffer to avoid allocation).
func (r *Redactor) Redact(dst, body []byte) ([]byte, int) {
	n := 0
	pos := 0
	r.eng.Each(body, func(s, e, p int) bool {
		if n == 0 {
			if cap(dst) < len(body) {
				dst = make([]byte, 0, len(body)+len(body)/16)
			}
			dst = dst[:0]
		}
		dst = append(dst, body[pos:s]...)
		dst = append(dst, r.ph[r.owner[p]]...)
		pos = e
		n++
		return true
	})
	if n == 0 {
		return body, 0
	}
	return append(dst, body[pos:]...), n
}

// Count returns the number of matches (used to verify no variant survives).
func (r *Redactor) Count(body []byte) int {
	n := 0
	r.eng.Each(body, func(s, e, p int) bool { n++; return true })
	return n
}
