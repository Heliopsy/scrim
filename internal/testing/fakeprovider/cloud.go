// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
)

// CloudKind is a cloud provider front end the fake can stand in for.
type CloudKind string

// Cloud provider front ends.
const (
	// Bedrock is the Amazon Bedrock runtime: InvokeModel and
	// InvokeModelWithResponseStream with Anthropic bodies, the streaming
	// reply in Amazon's binary event stream, count-tokens, and the
	// inference-profile listing Claude Code asks for at start.
	Bedrock CloudKind = "bedrock"
	// BedrockMantle serves the Anthropic Messages API, SigV4 service
	// bedrock-mantle.
	BedrockMantle CloudKind = "bedrock-mantle"
	// AnthropicAWS is Claude Platform on AWS: the Anthropic Messages API,
	// SigV4 service aws-external-anthropic or a bearer API key, and the
	// anthropic-workspace-id header on every request.
	AnthropicAWS CloudKind = "anthropic-aws"
	// Foundry is Microsoft Foundry: the Anthropic Messages API under
	// /anthropic with an api-key header, or an Entra ID bearer token.
	Foundry CloudKind = "foundry"
	// Vertex is Google Vertex AI's Anthropic publisher: rawPredict and
	// streamRawPredict with the model in the path, Google access tokens.
	Vertex CloudKind = "vertex"
)

// CloudOptions configure a [Cloud].
type CloudOptions struct {
	Kind   CloudKind
	Region string
	// AccessKeyID, SecretAccessKey and SessionToken are the AWS credentials
	// a request must be signed with (SigV4), or APIKey the key it must carry.
	// A request that is not authenticated with them is refused like the real
	// provider refuses it.
	AccessKeyID, SecretAccessKey, SessionToken string
	APIKey                                     string
	// Tokens, when set, issues the bearer tokens a request must carry
	// (Vertex, Foundry with Entra ID).
	Tokens *TokenIssuer
	// Now is the clock signatures are checked against; default time.Now.
	Now func() time.Time
}

// CloudRequest is one request the front end received, as it arrived.
type CloudRequest struct {
	leak.Capture
	// Auth is "" when the request authenticated, else why it did not.
	Auth string
}

// Cloud is a cloud provider front end over a [Server]: it checks each
// request's authentication and wire format the way the provider does,
// translates it to the Anthropic Messages API the Server speaks, and its
// reply back. It is an http.Handler.
type Cloud struct {
	inner *Server
	opts  CloudOptions

	mu       sync.Mutex
	requests []CloudRequest
}

// NewCloud returns a front end for inner.
func NewCloud(inner *Server, o CloudOptions) *Cloud {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Cloud{inner: inner, opts: o}
}

// Requests returns every request received, in order.
func (c *Cloud) Requests() []CloudRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

// Service is the SigV4 signing name of an AWS kind.
func (k CloudKind) Service() string {
	switch k {
	case Bedrock:
		return "bedrock"
	case BedrockMantle:
		return "bedrock-mantle"
	case AnthropicAWS:
		return "aws-external-anthropic"
	}
	return ""
}

// ServeHTTP implements http.Handler.
func (c *Cloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	rec := CloudRequest{Capture: leak.Capture{Method: r.Method, Path: rawPath, RawQuery: rawQuery, Header: r.Header.Clone(), Body: body}}
	rec.Auth = c.authenticate(r, rawPath, rawQuery, body)
	c.mu.Lock()
	rec.Seq = len(c.requests) + 1
	c.requests = append(c.requests, rec)
	c.mu.Unlock()
	if rec.Auth != "" {
		c.deny(w, rec.Auth)
		return
	}
	switch c.opts.Kind {
	case Bedrock:
		c.bedrock(w, r, rawPath, body)
	case AnthropicAWS:
		if !strings.HasPrefix(r.Header.Get("anthropic-workspace-id"), "wrkspc_") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"type": "error", "error": map[string]any{
				"type": "invalid_request_error", "message": "anthropic-workspace-id header is required"}})
			return
		}
		c.forward(w, r, r.URL.Path, body)
	case Vertex:
		c.vertex(w, r, body)
	case Foundry:
		p, ok := strings.CutPrefix(r.URL.Path, "/anthropic/")
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "404", "message": "Resource not found"}})
			return
		}
		c.forward(w, r, "/"+p, body)
	default:
		c.forward(w, r, r.URL.Path, body)
	}
}

func (c *Cloud) deny(w http.ResponseWriter, why string) {
	switch c.opts.Kind {
	case Bedrock:
		w.Header().Set("x-amzn-ErrorType", "UnrecognizedClientException:http://internal.amazon.com/coral/com.amazon.coral.service/")
		writeJSON(w, http.StatusForbidden, map[string]any{"message": why})
	case Foundry:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "401",
			"message": "Access denied due to invalid subscription key or wrong API endpoint."}})
	default:
		writeJSON(w, http.StatusForbidden, map[string]any{"type": "error", "error": map[string]any{"type": "permission_error", "message": why}})
	}
}

// authenticate returns why the request is not authenticated, or "".
func (c *Cloud) authenticate(r *http.Request, rawPath, rawQuery string, body []byte) string {
	o := c.opts
	if o.Tokens != nil {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !o.Tokens.Valid(tok) {
			return "Request had invalid authentication credentials. Expected OAuth 2 access token."
		}
		return ""
	}
	if o.APIKey != "" {
		var got string
		switch o.Kind {
		case Foundry:
			got = r.Header.Get("api-key")
		default:
			got, _ = strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(o.APIKey)) != 1 {
			return "The security token included in the request is invalid."
		}
		return ""
	}
	return VerifySigV4(r.Method, rawPath, rawQuery, r.Host, r.Header, body, SigV4Key{
		AccessKeyID: o.AccessKeyID, SecretAccessKey: o.SecretAccessKey, SessionToken: o.SessionToken,
		Region: o.Region, Service: o.Kind.Service()}, o.Now())
}

// SigV4Key is what a SigV4 signature must have been made with.
type SigV4Key struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Region, Service                            string
}

// VerifySigV4 checks an AWS Signature Version 4 header signature the way AWS
// does and returns why it fails, or "". rawPath and rawQuery are the request
// target as sent. It is written from AWS's documentation, independently of
// scrim's signer.
func VerifySigV4(method, rawPath, rawQuery, host string, h http.Header, body []byte, k SigV4Key, now time.Time) string {
	auth := h.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return "Missing Authentication Token"
	}
	fields := map[string]string{}
	for p := range strings.SplitSeq(rest, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	cred := strings.Split(fields["Credential"], "/")
	if len(cred) != 5 || cred[4] != "aws4_request" {
		return "Authorization header is malformed"
	}
	if cred[0] != k.AccessKeyID {
		return "The security token included in the request is invalid."
	}
	if cred[2] != k.Region || cred[3] != k.Service {
		return fmt.Sprintf("Credential should be scoped to a valid region and service %s", k.Service)
	}
	amzDate := h.Get("X-Amz-Date")
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil || !strings.HasPrefix(amzDate, cred[1]) {
		return "X-Amz-Date is missing or does not match the credential scope"
	}
	if d := now.Sub(t); d > 5*time.Minute || d < -5*time.Minute {
		return "Signature expired"
	}
	if k.SessionToken != "" && h.Get("X-Amz-Security-Token") != k.SessionToken {
		return "The security token included in the request is invalid."
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	if !slices.Contains(signed, "host") || !slices.Contains(signed, "x-amz-date") ||
		(k.SessionToken != "" && !slices.Contains(signed, "x-amz-security-token")) {
		return "SignedHeaders must include host and x-amz-date"
	}
	var cr strings.Builder
	cr.WriteString(method + "\n")
	segs := strings.Split(rawPath, "/")
	for i, s := range segs {
		segs[i] = awsEscape(s)
	}
	cr.WriteString(strings.Join(segs, "/") + "\n")
	cr.WriteString(canonicalQuery(rawQuery) + "\n")
	for _, name := range signed {
		var v string
		if name == "host" {
			v = host
		} else {
			vals := h.Values(name)
			for i, x := range vals {
				vals[i] = strings.Join(strings.Fields(x), " ")
			}
			v = strings.Join(vals, ",")
		}
		cr.WriteString(name + ":" + v + "\n")
	}
	cr.WriteString("\n" + fields["SignedHeaders"] + "\n")
	sum := sha256.Sum256(body)
	cr.WriteString(hex.EncodeToString(sum[:]))
	crSum := sha256.Sum256([]byte(cr.String()))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + strings.Join(cred[1:], "/") + "\n" + hex.EncodeToString(crSum[:])
	mac := func(key []byte, s string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(s))
		return m.Sum(nil)
	}
	key := mac(mac(mac(mac([]byte("AWS4"+k.SecretAccessKey), cred[1]), cred[2]), cred[3]), "aws4_request")
	want := hex.EncodeToString(mac(key, toSign))
	if subtle.ConstantTimeCompare([]byte(want), []byte(fields["Signature"])) != 1 {
		return "The request signature we calculated does not match the signature you provided."
	}
	return ""
}

func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q string) string {
	if q == "" {
		return ""
	}
	var pairs []string
	for p := range strings.SplitSeq(q, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		dk, _ := url.QueryUnescape(k)
		dv, _ := url.QueryUnescape(v)
		pairs = append(pairs, awsEscape(dk)+"="+awsEscape(dv))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// forward sends the request on to the inner Server at path.
func (c *Cloud) forward(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	req := r.Clone(r.Context())
	req.URL.Path, req.URL.RawPath = path, ""
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	c.inner.ServeHTTP(w, req)
}

var vertexPath = regexp.MustCompile(`^/v1/projects/[^/]+/locations/[^/]+/publishers/anthropic/models/([^/:]+):(rawPredict|streamRawPredict)$`)

// vertex serves the Anthropic publisher's rawPredict and streamRawPredict.
func (c *Cloud) vertex(w http.ResponseWriter, r *http.Request, body []byte) {
	bad := func(status int, msg string) {
		writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": msg, "status": "INVALID_ARGUMENT"}})
	}
	m := vertexPath.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodPost || m == nil {
		bad(http.StatusNotFound, "The requested URL was not found on this server.")
		return
	}
	var req map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil {
		bad(http.StatusBadRequest, "Invalid JSON payload received.")
		return
	}
	if m[1] == "count-tokens" {
		c.forward(w, r, "/v1/messages/count_tokens", body)
		return
	}
	var version string
	if json.Unmarshal(req["anthropic_version"], &version) != nil || version != "vertex-2023-10-16" {
		bad(http.StatusBadRequest, "anthropic_version: vertex-2023-10-16 is required")
		return
	}
	if _, ok := req["model"]; ok {
		bad(http.StatusBadRequest, "model: Extra inputs are not permitted")
		return
	}
	delete(req, "anthropic_version")
	req["model"], _ = json.Marshal(m[1])
	stream := m[2] == "streamRawPredict"
	if s, ok := req["stream"]; ok {
		var v bool
		_ = json.Unmarshal(s, &v)
		stream = stream || v
	}
	req["stream"], _ = json.Marshal(stream)
	msg, _ := json.Marshal(req)
	c.forward(w, r, "/v1/messages", msg)
}

// bedrock serves the Bedrock runtime paths.
func (c *Cloud) bedrock(w http.ResponseWriter, r *http.Request, rawPath string, body []byte) {
	bad := func(status int, msg string) {
		w.Header().Set("x-amzn-ErrorType", "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/")
		writeJSON(w, status, map[string]any{"message": msg})
	}
	if r.Method == http.MethodGet && rawPath == "/inference-profiles" {
		// The listing belongs to the control plane host, not the runtime.
		writeJSON(w, http.StatusOK, map[string]any{"inferenceProfileSummaries": []any{}})
		return
	}
	parts := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	if r.Method != http.MethodPost || len(parts) != 3 || parts[0] != "model" {
		w.Header().Set("x-amzn-ErrorType", "UnknownOperationException:")
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "Unknown operation"})
		return
	}
	model, err := url.PathUnescape(parts[1])
	if err != nil || model == "" {
		bad(http.StatusBadRequest, "The provided model identifier is invalid.")
		return
	}
	action := parts[2]
	if action == "count-tokens" {
		var ct struct {
			Input struct {
				InvokeModel struct {
					Body string `json:"body"`
				} `json:"invokeModel"`
			} `json:"input"`
		}
		if json.Unmarshal(body, &ct) != nil || ct.Input.InvokeModel.Body == "" {
			bad(http.StatusBadRequest, "input.invokeModel.body is required")
			return
		}
		inner, err := base64.StdEncoding.DecodeString(ct.Input.InvokeModel.Body)
		if err != nil || !json.Valid(inner) {
			bad(http.StatusBadRequest, "input.invokeModel.body is not base64 of a JSON document")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"inputTokens": max(1, len(inner)/4)})
		return
	}
	stream := action == "invoke-with-response-stream"
	if action != "invoke" && !stream {
		bad(http.StatusBadRequest, "unsupported action "+action)
		return
	}
	var req map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil {
		bad(http.StatusBadRequest, "Malformed input request, please reformat your input and try again.")
		return
	}
	if _, ok := req["anthropic_version"]; !ok {
		bad(http.StatusBadRequest, "Malformed input request: #: required key [anthropic_version] not found, please reformat your input and try again.")
		return
	}
	for _, k := range []string{"model", "stream"} {
		if _, ok := req[k]; ok {
			bad(http.StatusBadRequest, "Malformed input request: #: extraneous key ["+k+"] is not permitted, please reformat your input and try again.")
			return
		}
	}
	delete(req, "anthropic_version")
	req["model"], _ = json.Marshal(model)
	req["stream"], _ = json.Marshal(stream)
	msg, _ := json.Marshal(req)
	if !stream {
		c.forward(w, r, "/v1/messages", msg)
		return
	}
	rec := httptest.NewRecorder()
	c.forward(rec, r, "/v1/messages", msg)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/event-stream") {
		bad(rec.Code, strings.TrimSpace(rec.Body.String()))
		return
	}
	w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
	w.Header().Set("x-amzn-bedrock-content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	for ev := range strings.SplitSeq(rec.Body.String(), "\n\n") {
		var data string
		for line := range strings.SplitSeq(ev, "\n") {
			if d, ok := strings.CutPrefix(line, "data: "); ok {
				data += d
			}
		}
		if data == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(data)), "p": "abcdefghijklmnopqrstuvwxyzABCDEF"[:len(data)%32]})
		frame, err := EventStreamFrame(map[string]string{":event-type": "chunk", ":content-type": "application/json", ":message-type": "event"}, payload)
		if err != nil {
			// Bedrock ends the stream with an exception the client sees.
			frame, _ = EventStreamFrame(map[string]string{":exception-type": "internalServerException", ":content-type": "application/json",
				":message-type": "exception"}, []byte(`{"message":"event too large"}`))
		}
		_, _ = w.Write(frame)
		if f != nil {
			f.Flush()
		}
	}
}

// MaxEventStreamFrame is the largest message Amazon's event stream allows
// (16 MiB of payload plus 128 KiB of headers).
const MaxEventStreamFrame = 16<<20 + 128<<10 + 16

// EventStreamFrame encodes one Amazon event stream message with string
// headers, in name order. It fails on a header name over 255 bytes, a value
// over 65535 bytes or a message over [MaxEventStreamFrame].
func EventStreamFrame(headers map[string]string, payload []byte) ([]byte, error) {
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var hb bytes.Buffer
	for _, n := range names {
		v := headers[n]
		if len(n) > math.MaxUint8 || len(v) > math.MaxUint16 {
			return nil, fmt.Errorf("event stream: header %.32q too long", n)
		}
		hb.WriteByte(byte(len(n)))
		hb.WriteString(n)
		hb.WriteByte(7)
		hb.Write(binary.BigEndian.AppendUint16(nil, uint16(len(v))))
		hb.WriteString(v)
	}
	if len(payload) > MaxEventStreamFrame || hb.Len() > MaxEventStreamFrame-16-len(payload) {
		return nil, errors.New("event stream: message too large")
	}
	total := 12 + hb.Len() + len(payload) + 4
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(total))
	out = binary.BigEndian.AppendUint32(out, uint32(hb.Len()))
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	out = append(out, hb.Bytes()...)
	out = append(out, payload...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out)), nil
}

// EventStreamMessage is one decoded event stream message with its string
// headers.
type EventStreamMessage struct {
	Headers map[string]string
	Payload []byte
}

// DecodeEventStream decodes a whole event stream body, checking both CRCs of
// every message.
func DecodeEventStream(b []byte) ([]EventStreamMessage, error) {
	var out []EventStreamMessage
	for len(b) > 0 {
		if len(b) < 16 {
			return out, errors.New("event stream: truncated message")
		}
		total, hlen := int(binary.BigEndian.Uint32(b)), int(binary.BigEndian.Uint32(b[4:]))
		if crc32.ChecksumIEEE(b[:8]) != binary.BigEndian.Uint32(b[8:]) {
			return out, errors.New("event stream: prelude CRC mismatch")
		}
		if total < 16 || total > len(b) || hlen > total-16 {
			return out, errors.New("event stream: bad lengths")
		}
		if crc32.ChecksumIEEE(b[:total-4]) != binary.BigEndian.Uint32(b[total-4:]) {
			return out, errors.New("event stream: message CRC mismatch")
		}
		m := EventStreamMessage{Headers: map[string]string{}, Payload: slices.Clone(b[12+hlen : total-4])}
		h := b[12 : 12+hlen]
		for len(h) > 0 {
			n := int(h[0])
			if len(h) < 1+n+1 {
				return out, errors.New("event stream: bad header")
			}
			name, typ := string(h[1:1+n]), h[1+n]
			h = h[2+n:]
			if typ != 7 || len(h) < 2 {
				return out, fmt.Errorf("event stream: header %s has type %d", name, typ)
			}
			l := int(binary.BigEndian.Uint16(h))
			if len(h) < 2+l {
				return out, errors.New("event stream: bad header")
			}
			m.Headers[name] = string(h[2 : 2+l])
			h = h[2+l:]
		}
		out = append(out, m)
		b = b[total:]
	}
	return out, nil
}

// TokenIssuer is a fake OAuth 2.0 token service: Google's token endpoint
// (service account JWT bearer grant, checked against the key's public key),
// the Google metadata server, and an Entra ID tenant's client credentials
// grant. It issues random tokens that [Cloud] accepts until they expire.
type TokenIssuer struct {
	// URL is where the issuer is served: the JWT audience it requires.
	URL string
	// ServiceAccount and PublicKey are the Google service account whose
	// signed assertions are accepted.
	ServiceAccount string
	PublicKey      *rsa.PublicKey
	// ClientID and ClientSecret are the Entra ID application accepted.
	ClientID, ClientSecret string

	mu       sync.Mutex
	tokens   map[string]time.Time
	requests []leak.Capture
	refused  []string
}

// Valid reports whether tok was issued and has not expired.
func (t *TokenIssuer) Valid(tok string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.tokens[tok]
	return ok && time.Now().Before(exp)
}

// Requests returns every token request received.
func (t *TokenIssuer) Requests() []leak.Capture {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.requests)
}

// Refused returns why each refused token request was refused.
func (t *TokenIssuer) Refused() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.refused)
}

func (t *TokenIssuer) issue(w http.ResponseWriter) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := "ya29.fake-" + base64.RawURLEncoding.EncodeToString(b)
	t.mu.Lock()
	if t.tokens == nil {
		t.tokens = map[string]time.Time{}
	}
	t.tokens[tok] = time.Now().Add(time.Hour)
	t.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
}

func (t *TokenIssuer) refuse(w http.ResponseWriter, why string) {
	t.mu.Lock()
	t.refused = append(t.refused, why)
	t.mu.Unlock()
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": why})
}

// ServeHTTP implements http.Handler.
func (t *TokenIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	t.mu.Lock()
	t.requests = append(t.requests, leak.Capture{Seq: len(t.requests) + 1, Method: r.Method, Path: r.URL.Path,
		RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
	t.mu.Unlock()
	form, _ := url.ParseQuery(string(body))
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/token":
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		t.issue(w)
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.refuse(w, "unsupported grant_type")
			return
		}
		if why := t.checkJWT(form.Get("assertion")); why != "" {
			t.refuse(w, why)
			return
		}
		t.issue(w)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		switch {
		case form.Get("grant_type") != "client_credentials":
			t.refuse(w, "AADSTS70003: unsupported grant type")
		case form.Get("client_id") != t.ClientID || subtle.ConstantTimeCompare([]byte(form.Get("client_secret")), []byte(t.ClientSecret)) != 1:
			t.refuse(w, "AADSTS7000215: Invalid client secret provided.")
		case form.Get("scope") != "https://ai.azure.com/.default":
			t.refuse(w, "AADSTS70011: The provided value for scope is not valid.")
		default:
			t.issue(w)
		}
	default:
		http.NotFound(w, r)
	}
}

// checkJWT verifies an RS256 assertion the way Google's token endpoint does.
func (t *TokenIssuer) checkJWT(a string) string {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return "malformed assertion"
	}
	var hdr struct{ Alg, Typ string }
	var cl struct {
		Iss, Scope, Aud string
		Iat, Exp        int64
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(cb, &cl) != nil {
		return "malformed assertion"
	}
	if hdr.Alg != "RS256" {
		return "unsupported alg"
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(t.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return "Invalid JWT Signature."
	}
	now := time.Now().Unix()
	switch {
	case cl.Iss != t.ServiceAccount:
		return "Invalid JWT: iss"
	case cl.Aud != t.URL+"/token":
		return "Invalid JWT: aud"
	case !strings.Contains(" "+cl.Scope+" ", " https://www.googleapis.com/auth/cloud-platform "):
		return "Invalid JWT: scope"
	case cl.Exp < now || cl.Iat > now+60 || cl.Exp-cl.Iat > 3600:
		return "Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe."
	}
	return ""
}
