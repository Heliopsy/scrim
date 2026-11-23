// SPDX-License-Identifier: AGPL-3.0-only

package fakeprovider

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The verifier against AWS's own signing test suite (the copy the tool proxy's
// signer is tested with).
func TestVerifySigV4AWSTestSuite(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "dataplane", "crates", "scrim-toolproxy", "testdata", "aws-sigv4-test-suite")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	key := SigV4Key{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", Region: "us-east-1", Service: "service"}
	for _, name := range []string{"get-vanilla", "get-vanilla-query", "get-vanilla-query-order-key-case", "get-vanilla-query-unreserved",
		"get-unreserved", "get-header-value-trim", "get-header-key-duplicate", "post-vanilla", "post-vanilla-query",
		"post-header-key-case", "post-header-key-sort", "post-header-value-case", "post-x-www-form-urlencoded", "post-sts-header-before"} {
		f, err := os.Open(filepath.Join(dir, name, "header-signed-request.txt"))
		if err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(f)
		line, _ := r.ReadString('\n')
		reqLine := strings.Fields(line)
		h := http.Header{}
		var last string
		for {
			l, err := r.ReadString('\n')
			l = strings.TrimRight(l, "\r\n")
			if l == "" || err != nil {
				break
			}
			if strings.HasPrefix(l, " ") && last != "" {
				vals := h.Values(last)
				vals[len(vals)-1] += "," + strings.TrimSpace(l)
				continue
			}
			k, v, _ := strings.Cut(l, ":")
			h.Add(k, v)
			last = k
		}
		body, _ := io.ReadAll(r)
		_ = f.Close()
		k := key
		if tok := h.Get("X-Amz-Security-Token"); tok != "" {
			k.SessionToken = tok
		}
		path, query, _ := strings.Cut(reqLine[1], "?")
		if why := VerifySigV4(reqLine[0], path, query, h.Get("Host"), h, body, k, now); why != "" {
			t.Errorf("%s: %s", name, why)
		}
		k.SecretAccessKey += "x"
		if VerifySigV4(reqLine[0], path, query, h.Get("Host"), h, body, k, now) == "" {
			t.Errorf("%s: verifies with the wrong secret", name)
		}
		if VerifySigV4(reqLine[0], path, query, h.Get("Host"), h, append(body, 'x'), key, now) == "" {
			t.Errorf("%s: verifies over a changed body", name)
		}
	}
}

func TestBedrockFrontEnd(t *testing.T) {
	inner := New(Options{Responder: func(Turn) Reply { return Reply{Text: "hello from bedrock"} }})
	cloud := NewCloud(inner, CloudOptions{Kind: Bedrock, Region: "us-east-1", APIKey: "bedrock-key-for-tests"})
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	post := func(path, auth, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	body := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`
	if r := post("/model/m/invoke", "wrong", body); r.StatusCode != http.StatusForbidden {
		t.Errorf("wrong key: %d", r.StatusCode)
	}
	if r := post("/model/m/invoke", "bedrock-key-for-tests", `{"model":"m","anthropic_version":"x","messages":[]}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("a model in the body is accepted: %d", r.StatusCode)
	}
	r := post("/model/us.anthropic.claude-x-v1:0/invoke-with-response-stream", "bedrock-key-for-tests", body)
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "application/vnd.amazon.eventstream" {
		t.Fatalf("stream: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	raw, _ := io.ReadAll(r.Body)
	msgs, err := DecodeEventStream(raw)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	var types []string
	for _, m := range msgs {
		var p struct{ Bytes string }
		if json.Unmarshal(m.Payload, &p) != nil || m.Headers[":event-type"] != "chunk" {
			t.Fatalf("frame: %v %s", m.Headers, m.Payload)
		}
		ev, _ := base64.StdEncoding.DecodeString(p.Bytes)
		var e struct {
			Type  string
			Delta struct{ Text string }
		}
		_ = json.Unmarshal(ev, &e)
		types = append(types, e.Type)
		text.WriteString(e.Delta.Text)
	}
	if text.String() != "hello from bedrock" || types[0] != "message_start" || types[len(types)-1] != "message_stop" {
		t.Errorf("stream text %q, events %v", text.String(), types)
	}
	ex := inner.Exchanges()
	if ex[len(ex)-1].Model != "us.anthropic.claude-x-v1:0" || !ex[len(ex)-1].Stream {
		t.Errorf("translated request: model %q stream %v", ex[len(ex)-1].Model, ex[len(ex)-1].Stream)
	}
	if got := cloud.Requests(); len(got) != 3 || got[0].Auth == "" || got[2].Auth != "" {
		t.Errorf("recorded requests: %+v", got)
	}
}
