// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdkconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// client speaks the AWS JSON 1.1 protocol of one service (Secrets Manager
// or Systems Manager) with SigV4 signing. The AWS SDK provides the
// credentials (its default chain, or STS role assumption) and the signer;
// the requests and responses are built here, because the SDK's service
// clients carry secret values as Go strings, which cannot be wiped. Values
// travel between secret.Value and the HTTP body through package wire.
type client struct {
	service string // signing name and endpoint label: "secretsmanager", "ssm"
	target  string // X-Amz-Target prefix: "secretsmanager", "AmazonSSM"
	s       *settings
	http    *http.Client
	signer  *v4.Signer

	mu       sync.Mutex
	ready    bool
	region   string
	endpoint string
	creds    *recorder
	// static holds the access keys resolved from references, wiped on
	// close.
	static []secret.Value
}

func newClient(s *settings, service, target string) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	return &client{
		service: service, target: target, s: s,
		http:   &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		signer: v4.NewSigner(),
	}
}

// apiError is a failed call. msg is safe to show: it never holds a value.
type apiError struct {
	kind   error
	code   string
	status int
	msg    string
	cause  error
	// deleted: the secret is scheduled for deletion.
	deleted bool
}

func (e *apiError) Error() string { return "aws: " + e.msg }

// codeError is the cause kept on a stores.Error for an error AWS returned:
// the error code and HTTP status only. AWS validation messages can quote
// request fields, the value included, so the message is never kept here.
type codeError struct {
	code   string
	status int
}

func (e codeError) Error() string { return fmt.Sprintf("aws %s (HTTP %d)", e.code, e.status) }

// setup loads the AWS configuration on first use: region, credentials from
// the default chain (environment, shared config and credentials files, web
// identity token, ECS container credentials, EC2 instance metadata) or from
// the configured static keys, and the role to assume on top. A failure is
// not cached, so a fixed environment is picked up on the next call.
func (c *client) setup(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ready {
		return nil
	}
	var opts []func(*sdkconfig.LoadOptions) error
	if c.s.region != "" {
		opts = append(opts, sdkconfig.WithRegion(c.s.region))
	}
	if c.s.profile != "" {
		opts = append(opts, sdkconfig.WithSharedConfigProfile(c.s.profile))
	}
	if c.s.keyIDRef != "" {
		p, err := c.staticProvider(ctx)
		if err != nil {
			return err
		}
		opts = append(opts, sdkconfig.WithCredentialsProvider(p))
	}
	cfg, err := sdkconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return &apiError{kind: stores.ErrInvalidRef, msg: "cannot load the AWS configuration: " + err.Error(), cause: err}
	}
	if cfg.Region == "" {
		return &apiError{kind: stores.ErrInvalidRef, msg: "no AWS region: set option region, AWS_REGION or a region in the shared config profile"}
	}
	provider := cfg.Credentials
	if c.s.roleARN != "" {
		stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
			if c.s.stsEndpoint != "" {
				o.BaseEndpoint = sdkaws.String(c.s.stsEndpoint)
			}
		})
		provider = sdkaws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, c.s.roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = c.s.sessionName
			if c.s.externalID != "" {
				o.ExternalID = sdkaws.String(c.s.externalID)
			}
			if c.s.roleDuration > 0 {
				o.Duration = c.s.roleDuration
			}
		}))
	}
	if provider == nil {
		return &apiError{kind: stores.ErrPermission, msg: "no AWS credentials"}
	}
	c.creds = &recorder{inner: provider}
	c.region = cfg.Region
	switch {
	case c.s.endpoint != nil:
		c.endpoint = c.s.endpoint.String()
	case cfg.BaseEndpoint != nil && *cfg.BaseEndpoint != "":
		c.endpoint = strings.TrimRight(*cfg.BaseEndpoint, "/")
	default:
		c.endpoint = defaultEndpoint(c.service, cfg.Region, c.s.fips)
	}
	c.ready = true
	return nil
}

// defaultEndpoint is the public regional endpoint of service.
func defaultEndpoint(service, region string, fips bool) string {
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	if fips {
		service += "-fips"
	}
	return "https://" + service + "." + region + "." + suffix
}

// staticProvider resolves the configured access keys once. The SDK takes
// credentials as Go strings, so each retrieval copies them out of the
// secret values; the copies live only as long as the SDK's own.
func (c *client) staticProvider(ctx context.Context) (sdkaws.CredentialsProvider, error) {
	id, err := c.s.resolve(ctx, c.s.keyIDRef)
	if err != nil {
		return nil, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s", optAccessKeyID, c.s.keyIDRef), cause: err}
	}
	key, err := c.s.resolve(ctx, c.s.secretKeyRef)
	if err != nil {
		id.Wipe()
		return nil, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("option %s: cannot resolve %s", optSecretAccessKey, c.s.secretKeyRef), cause: err}
	}
	if id.IsZero() || key.IsZero() {
		id.Wipe()
		key.Wipe()
		return nil, &apiError{kind: stores.ErrPermission, msg: fmt.Sprintf("options %s and %s must not resolve to empty values", optAccessKeyID, optSecretAccessKey)}
	}
	c.static = []secret.Value{id, key}
	return sdkaws.CredentialsProviderFunc(func(context.Context) (sdkaws.Credentials, error) {
		var cr sdkaws.Credentials
		_ = id.Expose(func(b []byte) error { cr.AccessKeyID = string(b); return nil })
		_ = key.Expose(func(b []byte) error { cr.SecretAccessKey = string(b); return nil })
		cr.Source = "scrim static keys"
		return cr, nil
	}), nil
}

// recorder remembers the last credentials retrieved, so the adapter can
// hand the secret key and session token to the redaction set.
type recorder struct {
	inner sdkaws.CredentialsProvider
	mu    sync.Mutex
	last  sdkaws.Credentials
}

func (r *recorder) Retrieve(ctx context.Context) (sdkaws.Credentials, error) {
	cr, err := r.inner.Retrieve(ctx)
	if err == nil {
		r.mu.Lock()
		r.last = cr
		r.mu.Unlock()
	}
	return cr, err
}

// credentials returns copies of the secret parts of the credentials in use.
func (c *client) credentials() []secret.Value {
	c.mu.Lock()
	var out []secret.Value
	for _, v := range c.static {
		_ = v.Expose(func(b []byte) error { out = append(out, secret.New(b)); return nil })
	}
	r := c.creds
	c.mu.Unlock()
	if r != nil {
		r.mu.Lock()
		if r.last.SecretAccessKey != "" {
			out = append(out, secret.FromString(r.last.SecretAccessKey))
		}
		if r.last.SessionToken != "" {
			out = append(out, secret.FromString(r.last.SessionToken))
		}
		r.mu.Unlock()
	}
	return out
}

func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.static {
		v.Wipe()
	}
	c.static = nil
	c.http.CloseIdleConnections()
}

// call sends one operation with body (JSON) and returns the response body,
// which the caller wipes. sensitive marks a request that carries a value:
// AWS's own error message is then dropped entirely, since validation
// messages can quote it.
func (c *client) call(ctx context.Context, op string, body *wire.Body, sensitive bool) ([]byte, error) {
	if err := c.setup(ctx); err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = io.Copy(h, body.Reader())
	hash := hex.EncodeToString(h.Sum(nil))
	var last error
	for attempt := range c.s.maxAttempts {
		if attempt > 0 {
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return nil, &apiError{kind: stores.ErrUnavailable, msg: "cancelled while retrying", cause: err}
			}
		}
		b, err, retry := c.once(ctx, op, body, hash, sensitive)
		if err == nil {
			return b, nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (c *client) once(ctx context.Context, op string, body *wire.Body, hash string, sensitive bool) ([]byte, error, bool) {
	actx, cancel := context.WithTimeout(ctx, c.s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodPost, c.endpoint+"/", body.Reader())
	if err != nil {
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build the request", cause: err}, false
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", c.target+"."+op)
	cr, err := c.creds.Retrieve(actx)
	if err != nil {
		kind, retry := stores.ErrPermission, false
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
			kind, retry = stores.ErrUnavailable, true
		}
		return nil, &apiError{kind: kind, msg: "cannot get AWS credentials (" + credentialHint(err) + ")", cause: err}, retry
	}
	if err := c.signer.SignHTTP(actx, cr, req, hash, c.service, c.region, time.Now()); err != nil {
		return nil, &apiError{kind: stores.ErrPermission, msg: "cannot sign the request", cause: err}, false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "AWS did not answer", cause: scrubNetError(err)}, true
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "cannot read the response", cause: err}, true
	}
	if resp.StatusCode == http.StatusOK {
		return b, nil, false
	}
	defer secret.WipeBytes(b)
	code, msg := parseError(resp.Header, b)
	kind, retry := classify(code, resp.StatusCode)
	e := &apiError{kind: kind, code: code, status: resp.StatusCode, cause: codeError{code: code, status: resp.StatusCode}}
	e.msg = code
	if e.msg == "" {
		e.msg = "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	if !sensitive && msg != "" {
		e.msg += ": " + wire.SafeDetail(msg)
	}
	// Secrets Manager refuses most operations on a secret scheduled for
	// deletion with InvalidRequestException; such a secret reads as gone.
	lower := strings.ToLower(msg)
	e.deleted = code == "InvalidRequestException" && (strings.Contains(lower, "deletion") || strings.Contains(lower, "deleted"))
	return nil, e, retry
}

// credentialHint names what the credential chain tried without quoting
// the provider's message in full, which may name files and profiles.
func credentialHint(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return wire.SafeDetail(msg)
}

// scrubNetError keeps the kind of a transport error but drops the request
// URL the http package puts in front of it.
func scrubNetError(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

func parseError(h http.Header, b []byte) (code, msg string) {
	var e struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Msg2    string `json:"Message"`
	}
	_ = json.Unmarshal(b, &e)
	code = e.Type
	if code == "" {
		code = e.Code
	}
	if code == "" {
		code = h.Get("X-Amzn-ErrorType")
	}
	if i := strings.LastIndexByte(code, '#'); i >= 0 {
		code = code[i+1:]
	}
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[:i]
	}
	msg = e.Message
	if msg == "" {
		msg = e.Msg2
	}
	return code, msg
}

// classify maps an AWS error code and status to an error kind, and says
// whether the call is worth retrying.
func classify(code string, status int) (error, bool) {
	switch code {
	case "ResourceNotFoundException", "ParameterNotFound", "ParameterVersionNotFound":
		return stores.ErrNotFound, false
	case "AccessDeniedException", "AccessDenied", "UnrecognizedClientException", "InvalidSignatureException",
		"ExpiredTokenException", "ExpiredToken", "IncompleteSignature", "MissingAuthenticationToken",
		"InvalidClientTokenId", "SignatureDoesNotMatch", "NotAuthorized", "DecryptionFailure",
		"EncryptionFailure", "InvalidKeyId", "KMSAccessDeniedException":
		return stores.ErrPermission, false
	case "ResourceExistsException", "ParameterAlreadyExists":
		return stores.ErrConflict, false
	case "ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded",
		"ThrottledException", "TooManyUpdates", "InternalServiceError", "InternalServerError",
		"InternalFailure", "ServiceUnavailable", "ServiceUnavailableException", "InternalServiceErrorException":
		return stores.ErrUnavailable, true
	case "ValidationException", "InvalidParameterException", "InvalidRequestException", "MalformedPolicyDocumentException",
		"ParameterLimitExceeded", "ParameterMaxVersionLimitExceeded", "HierarchyLevelLimitExceededException",
		"HierarchyTypeMismatchException", "UnsupportedParameterType", "ParameterPatternMismatchException",
		"InvalidAllowedPatternException", "LimitExceededException", "TooManyTagsError", "InvalidResourceId",
		"InvalidResourceType", "InvalidFilterKey", "InvalidFilterOption", "InvalidFilterValue", "InvalidNextToken",
		"PreconditionNotMetException", "SerializationException":
		return stores.ErrInvalidRef, false
	}
	switch {
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return stores.ErrPermission, false
	case status == http.StatusNotFound:
		return stores.ErrNotFound, false
	case status == http.StatusTooManyRequests || status >= 500:
		return stores.ErrUnavailable, true
	}
	return stores.ErrInvalidRef, false
}

func backoff(attempt int) time.Duration {
	d := time.Duration(float64(100*time.Millisecond) * math.Pow(2, float64(attempt-1)))
	return jitter(min(d, 5*time.Second))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// jsonBody encodes head as a JSON object and, when field is set, adds it
// with v as a JSON string, or base64 when b64 is set. The body is wiped by
// the caller.
func jsonBody(head map[string]any, field string, v []byte, b64 bool) (*wire.Body, error) {
	buf, err := wire.AppendJSON(nil, head)
	if err != nil {
		return nil, err
	}
	if field == "" {
		return wire.NewBody(buf), nil
	}
	buf = buf[:len(buf)-1]
	if len(head) > 0 {
		buf = append(buf, ',')
	}
	buf, _ = wire.AppendQuoted(buf, []byte(field))
	buf = append(buf, ':')
	if b64 {
		buf = appendBase64(buf, v)
	} else if buf, err = wire.AppendQuoted(buf, v); err != nil {
		secret.WipeBytes(buf)
		return nil, err
	}
	return wire.NewBody(append(buf, '}')), nil
}

// newToken returns a random UUID (version 4), the idempotency token AWS
// asks for on every new secret version.
func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b[:])
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

// epoch is a timestamp as the JSON protocol sends it: seconds since the
// epoch, with a fraction.
type epoch struct{ time.Time }

func (e *epoch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	sec, frac := math.Modf(f)
	e.Time = time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return nil
}

type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// accountOf returns the account ID of an ARN, or "".
func accountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

func appendBase64(dst, v []byte) []byte {
	n := base64.StdEncoding.EncodedLen(len(v))
	dst = slices.Grow(dst, n+2)
	dst = append(dst, '"')
	start := len(dst)
	dst = dst[:start+n]
	base64.StdEncoding.Encode(dst[start:], v)
	return append(dst, '"')
}
