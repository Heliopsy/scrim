// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/placeholder"
)

// placeholderPattern finds scrim placeholders: `⟦scrim:<slug>:<vv><tag>⟧`.
var placeholderPattern = regexp.MustCompile(`⟦scrim:[a-z0-9-]{1,48}:[0-9a-f]{18}⟧`)

// readVerbs are the statements the tool runs, by first keyword.
var readVerbs = map[Kind][]string{
	Postgres: {"SELECT", "WITH", "VALUES", "TABLE", "SHOW", "EXPLAIN"},
	MySQL:    {"SELECT", "WITH", "VALUES", "TABLE", "SHOW", "EXPLAIN", "DESCRIBE", "DESC"},
}

// writeWords are keywords refused anywhere outside literals, comments and
// quoted identifiers: they write (a data-modifying WITH, SELECT INTO, SELECT
// ... INTO OUTFILE), lock rows, or change the schema. The read-only
// transaction refuses most of them on its own; refusing them here means the
// statement is never sent.
var writeWords = []string{
	"INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "INTO", "TRUNCATE", "DROP", "ALTER", "CREATE",
	"GRANT", "REVOKE", "COPY", "CALL", "OUTFILE", "DUMPFILE", "LOCK", "VACUUM", "REINDEX", "CLUSTER",
}

// statement is a checked statement ready to bind: the SQL with every literal
// that held a placeholder replaced by a parameter marker, and the parameter
// texts in bind order, placeholders still in them.
type statement struct {
	sql  string
	args []string
	// literals counts the parameters made from string literals.
	literals int
}

// prepare checks src as a single read statement for kind and turns string
// literals holding placeholders into parameters after params. It never
// substitutes a value: that happens on the parameter texts, which reach the
// server only as bound parameters.
func prepare(kind Kind, src string, params []string) (*statement, error) {
	s := &scanner{kind: kind, src: src}
	if err := s.run(); err != nil {
		return nil, err
	}
	if s.verb == "" {
		return nil, Refused("the statement is empty")
	}
	if !slices.Contains(readVerbs[kind], s.verb) {
		return nil, Refused("only read statements run here (%s); %s is refused", strings.Join(readVerbs[kind], ", "), s.verb)
	}
	if s.write != "" {
		return nil, Refused("%s is refused: the database tool only reads", s.write)
	}
	st := &statement{literals: len(s.literals)}
	var b strings.Builder
	last := 0
	switch kind {
	case Postgres:
		if s.maxParam > len(params) {
			return nil, Refused("the statement uses $%d but %d parameters were given", s.maxParam, len(params))
		}
		st.args = append(slices.Clone(params), make([]string, 0, len(s.literals))...)
		for i, l := range s.literals {
			b.WriteString(src[last:l.start])
			b.WriteString("$" + strconv.Itoa(len(params)+i+1))
			last = l.end
			st.args = append(st.args, l.text)
		}
	case MySQL:
		if s.markers != len(params) {
			return nil, Refused("the statement has %d ? markers but %d parameters were given", s.markers, len(params))
		}
		// Bind order is text order: explicit ? markers and literals as they
		// appear.
		pi := 0
		li := 0
		for _, pos := range s.order {
			if pos.literal {
				l := s.literals[li]
				li++
				b.WriteString(src[last:l.start])
				b.WriteString("?")
				last = l.end
				st.args = append(st.args, l.text)
				continue
			}
			st.args = append(st.args, params[pi])
			pi++
		}
	}
	b.WriteString(src[last:s.end])
	st.sql = strings.TrimSpace(b.String())
	return st, nil
}

type literal struct {
	start, end int
	text       string
}

type bindPos struct{ literal bool }

type scanner struct {
	kind     Kind
	src      string
	i        int
	end      int // end of the statement, before a trailing semicolon
	verb     string
	write    string
	literals []literal
	order    []bindPos
	maxParam int
	markers  int
	// identEnd is where the last bare word ended, to find string prefixes
	// such as E'...' that touch the quote.
	identEnd   int
	identStart int
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentByte(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' || c == '$' }

func (s *scanner) run() error {
	src := s.src
	s.end = len(src)
	s.identEnd = -1
	for s.i < len(src) {
		c := src[s.i]
		switch {
		case strings.HasPrefix(src[s.i:], placeholder.Open):
			return Refused("a placeholder may only appear inside a string literal")
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			s.i++
		case c == '-' && strings.HasPrefix(src[s.i:], "--") && s.dashComment():
			s.lineComment()
		case c == '#' && s.kind == MySQL:
			s.lineComment()
		case c == '/' && strings.HasPrefix(src[s.i:], "/*"):
			if err := s.blockComment(); err != nil {
				return err
			}
		case c == '\'':
			if err := s.quoted('\'', true); err != nil {
				return err
			}
		case c == '"':
			if err := s.quoted('"', s.kind == MySQL); err != nil {
				return err
			}
		case c == '`' && s.kind == MySQL:
			if err := s.quoted('`', false); err != nil {
				return err
			}
		case c == '$' && s.kind == Postgres:
			if err := s.dollar(); err != nil {
				return err
			}
		case c == '?' && s.kind == MySQL:
			s.markers++
			s.order = append(s.order, bindPos{})
			s.i++
		case c == ';':
			s.end = s.i
			s.i++
			if err := s.onlyTrailing(); err != nil {
				return err
			}
			return nil
		case isIdentStart(c):
			s.word()
		case c >= '0' && c <= '9':
			for s.i < len(src) && (isIdentByte(src[s.i]) || src[s.i] == '.') && !s.atPlaceholder() {
				s.i++
			}
		default:
			s.i++
		}
	}
	return nil
}

// dashComment reports whether "--" at s.i starts a comment: always in
// PostgreSQL, and in MySQL only when followed by whitespace, a control
// character or the end.
func (s *scanner) dashComment() bool {
	if s.kind != MySQL {
		return true
	}
	if s.i+2 >= len(s.src) {
		return true
	}
	c := s.src[s.i+2]
	return c <= ' '
}

func (s *scanner) lineComment() {
	j := strings.IndexByte(s.src[s.i:], '\n')
	if j < 0 {
		s.i = len(s.src)
		return
	}
	s.i += j + 1
}

func (s *scanner) blockComment() error {
	if s.kind == MySQL && strings.HasPrefix(s.src[s.i:], "/*!") {
		return Refused("MySQL executable comments (/*! ... */) are refused")
	}
	depth := 0
	for s.i < len(s.src) {
		switch {
		case strings.HasPrefix(s.src[s.i:], "/*"):
			if depth > 0 && s.kind == MySQL {
				s.i += 2
				continue
			}
			depth++
			s.i += 2
		case strings.HasPrefix(s.src[s.i:], "*/"):
			depth--
			s.i += 2
			if depth == 0 {
				return nil
			}
		default:
			s.i++
		}
	}
	return Refused("unterminated comment")
}

// quoted consumes a quoted token starting at s.i. str says it is a string
// literal (rather than an identifier); literals holding a placeholder become
// parameters.
func (s *scanner) quoted(q byte, str bool) error {
	start := s.i
	prefix := ""
	if s.identEnd == start {
		prefix = strings.ToUpper(s.src[s.identStart:s.identEnd])
		start = s.identStart
	} else if s.kind == Postgres && start >= 2 && s.src[start-2:start] == "U&" {
		prefix = "U&"
		start -= 2
	}
	backslash := (s.kind == MySQL && str) || (s.kind == Postgres && prefix == "E")
	s.i++
	var text strings.Builder
	hasBackslash := false
	for {
		if s.i >= len(s.src) {
			return Refused("unterminated quoted text")
		}
		c := s.src[s.i]
		switch {
		case backslash && c == '\\':
			hasBackslash = true
			if s.i+1 < len(s.src) {
				text.WriteByte(c)
				text.WriteByte(s.src[s.i+1])
			}
			s.i += 2
			continue
		case c == q && s.i+1 < len(s.src) && s.src[s.i+1] == q:
			text.WriteByte(q)
			s.i += 2
			continue
		case c == q:
			s.i++
		default:
			text.WriteByte(c)
			s.i++
			continue
		}
		break
	}
	s.identEnd = -1
	t := text.String()
	if !strings.Contains(t, placeholder.Open) {
		return nil
	}
	if !str {
		return Refused("a placeholder may only appear inside a string literal, not a quoted identifier")
	}
	if prefix != "" {
		return Refused("a placeholder may only appear inside a plain string literal, not a %s'...' literal", prefix)
	}
	if hasBackslash {
		return Refused("a string literal holding a placeholder may not use backslash escapes")
	}
	s.literals = append(s.literals, literal{start: start, end: s.i, text: t})
	s.order = append(s.order, bindPos{literal: true})
	return nil
}

// dollar handles $ in PostgreSQL: a parameter ($1), part of an identifier,
// or a dollar-quoted string.
func (s *scanner) dollar() error {
	src := s.src
	if s.i > 0 && isIdentByte(src[s.i-1]) {
		s.i++
		return nil
	}
	j := s.i + 1
	if j < len(src) && src[j] >= '0' && src[j] <= '9' {
		for j < len(src) && src[j] >= '0' && src[j] <= '9' {
			j++
		}
		n, err := strconv.Atoi(src[s.i+1 : j])
		if err != nil || n < 1 || n > 65535 {
			return Refused("bad parameter number %s", src[s.i:j])
		}
		s.maxParam = max(s.maxParam, n)
		s.i = j
		return nil
	}
	for j < len(src) && src[j] != '$' && isIdentByte(src[j]) && !strings.HasPrefix(src[j:], placeholder.Open) {
		j++
	}
	if j >= len(src) || src[j] != '$' || (j > s.i+1 && !isIdentStart(src[s.i+1])) {
		s.i++
		return nil
	}
	tag := src[s.i : j+1]
	k := strings.Index(src[j+1:], tag)
	if k < 0 {
		return Refused("unterminated dollar-quoted string")
	}
	body := src[j+1 : j+1+k]
	if strings.Contains(body, placeholder.Open) {
		return Refused("a placeholder may only appear inside a plain string literal, not a dollar-quoted one")
	}
	s.i = j + 1 + k + len(tag)
	return nil
}

func (s *scanner) atPlaceholder() bool { return strings.HasPrefix(s.src[s.i:], placeholder.Open) }

func (s *scanner) word() {
	start := s.i
	for s.i < len(s.src) && isIdentByte(s.src[s.i]) && !s.atPlaceholder() {
		s.i++
	}
	s.identStart, s.identEnd = start, s.i
	w := strings.ToUpper(s.src[start:s.i])
	if s.verb == "" {
		s.verb = w
	}
	if s.write == "" && slices.Contains(writeWords, w) {
		s.write = w
	}
}

// onlyTrailing accepts whitespace and comments after a semicolon; anything
// else is a second statement.
func (s *scanner) onlyTrailing() error {
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			s.i++
		case c == '-' && strings.HasPrefix(s.src[s.i:], "--") && s.dashComment():
			s.lineComment()
		case c == '#' && s.kind == MySQL:
			s.lineComment()
		case c == '/' && strings.HasPrefix(s.src[s.i:], "/*"):
			if err := s.blockComment(); err != nil {
				return err
			}
		default:
			return Refused("only one statement runs per call")
		}
	}
	return nil
}

// placeholdersIn lists the placeholders in text.
func placeholdersIn(text string) []string { return placeholderPattern.FindAllString(text, -1) }
