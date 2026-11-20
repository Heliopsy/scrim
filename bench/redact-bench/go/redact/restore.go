package redact

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// Table maps placeholder hash (12 hex) -> real value (raw and JSON-escaped).
type Table struct {
	m map[[12]byte]int32
	v [][]byte // raw value
	j [][]byte // JSON-escaped value (for input_json_delta)
}

func NewTable(secrets [][]byte, key []byte) *Table {
	t := &Table{m: make(map[[12]byte]int32, len(secrets))}
	for i, s := range secrets {
		ph := Placeholder(key, s)
		var k [12]byte
		copy(k[:], ph[7:19])
		if _, dup := t.m[k]; !dup {
			t.m[k] = int32(i)
		}
		t.v = append(t.v, s)
		t.j = append(t.j, AppendJSONEscaped(nil, s, false, false))
	}
	return t
}

func isHex(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') }

// shapeByte reports whether c can be at offset k of a placeholder.
func shapeByte(k int, c byte) bool {
	switch {
	case k < 7:
		return c == phOpen[k]
	case k < 19:
		return isHex(c)
	default:
		return c == phClose[k-19]
	}
}

func isPlaceholder(b []byte) bool {
	for k := 0; k < PlaceholderLen; k++ {
		if !shapeByte(k, b[k]) {
			return false
		}
	}
	return true
}

func isPlaceholderPrefix(b []byte) bool {
	for k := range b {
		if !shapeByte(k, b[k]) {
			return false
		}
	}
	return true
}

// substitute appends p to dst with known placeholders replaced; returns the
// start of a trailing incomplete-placeholder suffix to hold back (len(p) if none)
// and whether any replacement happened.
func (t *Table) substitute(dst, p []byte, jsonEsc bool) ([]byte, int, bool) {
	pos, i, hold := 0, 0, len(p)
	replaced := false
	for {
		j := bytes.IndexByte(p[i:], 0xE2)
		if j < 0 {
			break
		}
		j += i
		if len(p)-j >= PlaceholderLen {
			if isPlaceholder(p[j : j+PlaceholderLen]) {
				var k [12]byte
				copy(k[:], p[j+7:j+19])
				if idx, ok := t.m[k]; ok {
					dst = append(dst, p[pos:j]...)
					if jsonEsc {
						dst = append(dst, t.j[idx]...)
					} else {
						dst = append(dst, t.v[idx]...)
					}
					pos = j + PlaceholderLen
					i = pos
					replaced = true
					continue
				}
			}
		} else if isPlaceholderPrefix(p[j:]) {
			hold = j
			break
		}
		i = j + 1
	}
	return append(dst, p[pos:hold]...), hold, replaced
}

type block struct {
	held  []byte
	dtype uint8 // 0 none, 1 text, 2 thinking, 3 input_json
}

var dtypeName = [...]string{"", "text_delta", "thinking_delta", "input_json_delta"}
var dtypeField = [...]string{"", "text", "thinking", "partial_json"}

// Restorer is a streaming SSE restorer for one response.
type Restorer struct {
	t      *Table
	in     []byte
	blocks []block
	p      []byte // scratch: held + new text
	e      []byte // scratch: emitted text
	ev     deltaEvent
}

type deltaEvent struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

type stopEvent struct {
	Index int `json:"index"`
}

func NewRestorer(t *Table) *Restorer {
	return &Restorer{t: t, in: make([]byte, 0, 8192), p: make([]byte, 0, 256), e: make([]byte, 0, 256)}
}

func (r *Restorer) Reset() {
	r.in = r.in[:0]
	for i := range r.blocks {
		r.blocks[i].held = r.blocks[i].held[:0]
		r.blocks[i].dtype = 0
	}
	r.blocks = r.blocks[:0]
}

var sep = []byte("\n\n")

// Feed consumes one chunk and appends restored output to dst.
func (r *Restorer) Feed(dst, chunk []byte) []byte {
	buf := chunk
	if len(r.in) > 0 {
		r.in = append(r.in, chunk...)
		buf = r.in
	}
	off := 0
	for {
		k := bytes.Index(buf[off:], sep)
		if k < 0 {
			break
		}
		end := off + k + 2
		dst = r.event(dst, buf[off:end])
		off = end
	}
	rest := buf[off:]
	if len(r.in) > 0 {
		n := copy(r.in, rest)
		r.in = r.in[:n]
	} else {
		r.in = append(r.in, rest...)
	}
	return dst
}

// Finish flushes held text of open blocks (index order) and any trailing partial event.
func (r *Restorer) Finish(dst []byte) []byte {
	idx := make([]int, 0)
	for i := range r.blocks {
		if len(r.blocks[i].held) > 0 {
			idx = append(idx, i)
		}
	}
	sort.Ints(idx)
	for _, i := range idx {
		dst = r.flush(dst, i)
	}
	dst = append(dst, r.in...)
	r.in = r.in[:0]
	return dst
}

func (r *Restorer) blk(i int) *block {
	for len(r.blocks) <= i {
		r.blocks = append(r.blocks, block{})
	}
	return &r.blocks[i]
}

func (r *Restorer) writeDelta(dst []byte, idx int, dt uint8, text []byte) []byte {
	dst = append(dst, `event: content_block_delta`+"\n"+`data: {"type":"content_block_delta","index":`...)
	dst = strconv.AppendInt(dst, int64(idx), 10)
	dst = append(dst, `,"delta":{"type":"`...)
	dst = append(dst, dtypeName[dt]...)
	dst = append(dst, `","`...)
	dst = append(dst, dtypeField[dt]...)
	dst = append(dst, `":"`...)
	dst = AppendJSONEscaped(dst, text, false, false)
	return append(dst, "\"}}\n\n"...)
}

func (r *Restorer) flush(dst []byte, i int) []byte {
	b := &r.blocks[i]
	if len(b.held) == 0 {
		return dst
	}
	dst = r.writeDelta(dst, i, b.dtype, b.held)
	b.held = b.held[:0]
	return dst
}

const maxIndex = 1 << 16

// parseEvent splits "event: X\ndata: Y\n\n". ok=false for any other shape.
func parseEvent(ev []byte) (name, data []byte, ok bool) {
	body := ev[:len(ev)-2]
	nl := bytes.IndexByte(body, '\n')
	if nl < 0 {
		return nil, nil, false
	}
	l1, l2 := body[:nl], body[nl+1:]
	if !bytes.HasPrefix(l1, []byte("event:")) || !bytes.HasPrefix(l2, []byte("data:")) || bytes.IndexByte(l2, '\n') >= 0 {
		return nil, nil, false
	}
	name, data = l1[6:], l2[5:]
	if len(name) > 0 && name[0] == ' ' {
		name = name[1:]
	}
	if len(data) > 0 && data[0] == ' ' {
		data = data[1:]
	}
	return name, data, true
}

func (r *Restorer) event(dst, ev []byte) []byte {
	name, data, ok := parseEvent(ev)
	if !ok {
		return append(dst, ev...)
	}
	switch string(name) {
	case "content_block_delta":
		r.ev = deltaEvent{}
		if json.Unmarshal(data, &r.ev) != nil || r.ev.Index < 0 || r.ev.Index >= maxIndex {
			return append(dst, ev...)
		}
		var dt uint8
		var s string
		switch r.ev.Delta.Type {
		case "text_delta":
			dt, s = 1, r.ev.Delta.Text
		case "thinking_delta":
			dt, s = 2, r.ev.Delta.Thinking
		case "input_json_delta":
			dt, s = 3, r.ev.Delta.PartialJSON
		default: // signature_delta, citations_delta, ...: byte-identical passthrough
			return append(dst, ev...)
		}
		b := r.blk(r.ev.Index)
		b.dtype = dt
		hadHeld := len(b.held) > 0
		r.p = append(append(r.p[:0], b.held...), s...)
		var hold int
		var replaced bool
		r.e, hold, replaced = r.t.substitute(r.e[:0], r.p, dt == 3)
		b.held = append(b.held[:0], r.p[hold:]...)
		if !hadHeld && !replaced && hold == len(r.p) {
			return append(dst, ev...)
		}
		if len(r.e) == 0 {
			return dst
		}
		return r.writeDelta(dst, r.ev.Index, dt, r.e)
	case "content_block_stop":
		var st stopEvent
		if json.Unmarshal(data, &st) != nil || st.Index < 0 || st.Index >= maxIndex {
			return append(dst, ev...)
		}
		if st.Index < len(r.blocks) {
			dst = r.flush(dst, st.Index)
		}
		return append(dst, ev...)
	}
	return append(dst, ev...)
}
