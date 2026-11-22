// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Limits of PUT /v1/sessions/self/values.
const (
	// MaxSessionValues bounds the values one session registers.
	MaxSessionValues = 1000
	// MaxSessionValuesSize bounds the request body.
	MaxSessionValuesSize = 4 << 20
	maxValueName         = 512
)

// ToolSessionValues is the audit tool name of a registration.
const ToolSessionValues = "session_values"

// EncodeValues frames values for PUT /v1/sessions/self/values: for each, the
// name's length as a uvarint, the name, the value's length as a uvarint and
// the value. The returned buffer holds the values; wipe it after sending.
func EncodeValues(values []NamedValue) ([]byte, error) {
	var out []byte
	var tmp [binary.MaxVarintLen64]byte
	for _, v := range values {
		out = append(out, tmp[:binary.PutUvarint(tmp[:], uint64(len(v.Name)))]...)
		out = append(out, v.Name...)
		err := v.Value.Expose(func(b []byte) error {
			out = append(out, tmp[:binary.PutUvarint(tmp[:], uint64(len(b)))]...)
			out = append(out, b...)
			return nil
		})
		if err != nil {
			secret.WipeBytes(out)
			return nil, err
		}
	}
	return out, nil
}

// DecodeValues parses EncodeValues framing. Each value is copied into its
// own secret.Value; the caller wipes body.
func DecodeValues(body []byte) ([]NamedValue, error) {
	var out []NamedValue
	fail := func(msg string) ([]NamedValue, error) {
		for _, v := range out {
			v.Value.Wipe()
		}
		return nil, errors.New(msg)
	}
	r := bytes.NewReader(body)
	for r.Len() > 0 {
		if len(out) == MaxSessionValues {
			return fail("more than " + strconv.Itoa(MaxSessionValues) + " values")
		}
		n, err := binary.ReadUvarint(r)
		if err != nil || n > maxValueName || n > uint64(r.Len()) {
			return fail("malformed value name")
		}
		name := make([]byte, n)
		_, _ = io.ReadFull(r, name)
		if !utf8.Valid(name) {
			return fail("value name is not UTF-8")
		}
		n, err = binary.ReadUvarint(r)
		if err != nil || n == 0 || n > uint64(r.Len()) || n > agenttools.MaxValueSize {
			return fail("malformed value")
		}
		off := len(body) - r.Len()
		v := secret.New(body[off : off+int(n)])
		_, _ = r.Seek(int64(n), io.SeekCurrent)
		out = append(out, NamedValue{Name: string(name), Value: v})
	}
	return out, nil
}

// sessionValues registers the body's values for the caller's session.
func (s *Server) sessionValues(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if id.Source != identity.SourceSession {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "only a session registers project values"))
		return
	}
	if s.SessionValues == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "this scrim process does not take session values"))
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/octet-stream" {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the values must be sent as application/octet-stream"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxSessionValuesSize+1))
	if err != nil || len(body) > MaxSessionValuesSize {
		secret.WipeBytes(body)
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "the values are larger than %d bytes", MaxSessionValuesSize))
		return
	}
	values, err := DecodeValues(body)
	secret.WipeBytes(body)
	if err != nil {
		writeError(w, agenttools.Errorf(agenttools.CodeInvalid, "%s", err.Error()))
		return
	}
	entry := agenttools.AuditEntry{Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source), SessionID: id.SessionID,
		UID: id.Peer.UID, PID: id.Peer.PID, Tool: ToolSessionValues, Outcome: agenttools.OutcomeOK,
		Detail: strconv.Itoa(len(values)) + " project values registered for redaction"}
	n := len(values)
	if err := s.SessionValues(r.Context(), id.SessionID, values); err != nil {
		s.logger().Warn("registering project values failed", "session", id.SessionID, "error", err)
		entry.Outcome, entry.Detail = agenttools.OutcomeError, "registering project values failed"
		s.audit(r.Context(), entry)
		writeError(w, agenttools.Errorf(agenttools.CodeUnavailable, "the values could not be added to the redaction set"))
		return
	}
	s.audit(r.Context(), entry)
	writeJSON(w, http.StatusOK, SessionValuesOutput{Registered: n})
}

// SessionValuesOutput is the answer of PUT /v1/sessions/self/values.
type SessionValuesOutput struct {
	Registered int `json:"registered"`
}

// RegisterValues adds values found in the session's project files to the
// redaction set for this session, replacing what it registered before. It
// returns once the data plane redacts them. The values are not wiped: the
// caller owns them.
func (c *Client) RegisterValues(ctx context.Context, values []NamedValue) (SessionValuesOutput, error) {
	body, err := EncodeValues(values)
	if err != nil {
		return SessionValuesOutput{}, agenttools.Errorf(agenttools.CodeInternal, "a value was wiped before it was sent")
	}
	defer secret.WipeBytes(body)
	var out SessionValuesOutput
	return out, c.do(ctx, http.MethodPut, "/sessions/self/values", nil, bytes.NewReader(body), "application/octet-stream", &out)
}
