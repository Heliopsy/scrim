// SPDX-License-Identifier: AGPL-3.0-only

package aws

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/agentcache"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

var (
	_ stores.AgentAccess      = (*SecretsManager)(nil)
	_ stores.AgentFederation  = (*SecretsManager)(nil)
	_ stores.SessionForgetter = (*SecretsManager)(nil)
	_ stores.AgentAccess      = (*ParameterStore)(nil)
	_ stores.AgentFederation  = (*ParameterStore)(nil)
	_ stores.SessionForgetter = (*ParameterStore)(nil)
)

// agentCreds are the temporary credentials of a role an agent assumed with
// its identity token. The secret parts stay in secret.Value; arn is the
// assumed-role ARN (it names the role and the session, as CloudTrail
// shows it).
type agentCreds struct {
	keyID, secretKey, session secret.Value
	arn                       string
	expires                   time.Time
}

func (a *agentCreds) clone() *agentCreds {
	return &agentCreds{keyID: copyValue(a.keyID), secretKey: copyValue(a.secretKey), session: copyValue(a.session),
		arn: a.arn, expires: a.expires}
}

func (a *agentCreds) wipe() {
	a.keyID.Wipe()
	a.secretKey.Wipe()
	a.session.Wipe()
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error { out = secret.New(b); return nil })
	return out
}

// provider hands the credentials to the SDK signer. The signer takes Go
// strings, so each signature copies them out of the secret values, as the
// static key provider does; the copies live as long as the signing call.
func (a *agentCreds) provider() sdkaws.CredentialsProvider {
	return sdkaws.CredentialsProviderFunc(func(context.Context) (sdkaws.Credentials, error) {
		var cr sdkaws.Credentials
		_ = a.keyID.Expose(func(b []byte) error { cr.AccessKeyID = string(b); return nil })
		_ = a.secretKey.Expose(func(b []byte) error { cr.SecretAccessKey = string(b); return nil })
		_ = a.session.Expose(func(b []byte) error { cr.SessionToken = string(b); return nil })
		cr.Source, cr.CanExpire, cr.Expires = "scrim agent web identity", true, a.expires
		return cr, nil
	})
}

func newAgentCache() *agentcache.Cache[*agentCreds] {
	return agentcache.New((*agentCreds).clone, (*agentCreds).wipe)
}

// FederationMethods implements [stores.AgentFederation].
func (b *base) FederationMethods() []string { return []string{stores.FederationAWS} }

// ForgetSession implements [stores.SessionForgetter].
func (b *base) ForgetSession(id string) { b.agents.ForgetSession(id) }

// agentCredentials returns a copy of the role cred's agent assumed,
// assuming it with a fresh identity token when none is cached. The caller
// wipes it.
func (b *base) agentCredentials(ctx context.Context, op stores.Op, ref stores.Ref, cred stores.AgentCredential) (*agentCreds, error) {
	f := cred.Federation
	if f == nil || f.Method != stores.FederationAWS {
		return nil, b.unsupported(op, ref, "AWS checks an agent's own identity only by token exchange (identity.store-login method aws-web-identity)")
	}
	roleARN := f.Params["role-arn"]
	if !roleARNPattern.MatchString(roleARN) {
		return nil, &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrPermission,
			Detail: "the agent's role-arn is not an IAM role ARN (arn:aws:iam::<account>:role/<name>)"}
	}
	if !sessionPattern.MatchString(f.SessionName) {
		return nil, &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrPermission, Detail: "the agent's session name is not a valid RoleSessionName"}
	}
	dur := 15 * time.Minute
	if d := f.Params["duration"]; d != "" {
		pd, err := time.ParseDuration(d)
		if err != nil || pd < 15*time.Minute || pd > 12*time.Hour {
			return nil, b.invalid(op, ref, "duration must be between 15m and 12h")
		}
		dur = pd
	}
	if c, ok := b.agents.Get(f.Key); ok {
		return c, nil
	}
	if err := b.c.setup(ctx); err != nil {
		return nil, b.fail(op, ref, err)
	}
	if f.Token == nil {
		return nil, &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrPermission, Detail: "no identity token for the agent"}
	}
	jwt, err := f.Token()
	if err != nil {
		return nil, &stores.Error{Store: b.name, Op: op, Ref: ref, Kind: stores.ErrPermission, Detail: "no identity token for the agent", Cause: err}
	}
	c, err := b.c.assumeWithWebIdentity(ctx, roleARN, f.SessionName, dur, jwt)
	jwt.Wipe()
	if err != nil {
		return nil, b.fail(op, ref, err)
	}
	b.agents.Put(f.Key, f.Session, c, time.Until(c.expires))
	return c.clone(), nil
}

// stsEndpoint is where web identity calls go: assume-role.sts-endpoint,
// else the store's endpoint override (LocalStack serves every service on
// one), else the regional STS endpoint. setup must have run.
func (c *client) stsEndpoint() string {
	switch {
	case c.s.stsEndpoint != "":
		return strings.TrimRight(c.s.stsEndpoint, "/")
	case c.s.endpoint != nil:
		return strings.TrimRight(c.s.endpoint.String(), "/")
	}
	return defaultEndpoint("sts", c.region, c.s.fips)
}

type stsCredsXML struct {
	AccessKeyID     []byte `xml:"AccessKeyId"`
	SecretAccessKey []byte `xml:"SecretAccessKey"`
	SessionToken    []byte `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type assumeResultXML struct {
	Result struct {
		Credentials     stsCredsXML `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn string `xml:"Arn"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

func (r *assumeResultXML) wipe() {
	secret.WipeBytes(r.Result.Credentials.AccessKeyID)
	secret.WipeBytes(r.Result.Credentials.SecretAccessKey)
	secret.WipeBytes(r.Result.Credentials.SessionToken)
}

// assumeWithWebIdentity calls STS AssumeRoleWithWebIdentity, which is not
// signed: the identity token is the credential. The request and response
// are built here so the token and the returned keys stay out of Go strings
// (the XML decoder copies character data into the byte fields, which are
// wiped). AWS's error message is never kept, only its code.
func (c *client) assumeWithWebIdentity(ctx context.Context, roleARN, session string, dur time.Duration, jwt secret.Value) (*agentCreds, error) {
	buf := []byte("Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=")
	buf = appendQueryEscape(buf, []byte(roleARN))
	buf = append(buf, "&RoleSessionName="...)
	buf = appendQueryEscape(buf, []byte(session))
	buf = append(buf, "&DurationSeconds="+strconv.Itoa(int(dur/time.Second))+"&WebIdentityToken="...)
	_ = jwt.Expose(func(b []byte) error { buf = appendQueryEscape(buf, b); return nil })
	body := wire.NewBody(buf)
	defer body.Wipe()

	actx, cancel := context.WithTimeout(ctx, c.s.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodPost, c.stsEndpoint()+"/", body.Reader())
	if err != nil {
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: "cannot build the STS request", cause: err}
	}
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "STS did not answer", cause: scrubNetError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := wire.ReadBody(resp.Body)
	if err != nil {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "cannot read the STS response", cause: err}
	}
	defer secret.WipeBytes(b)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code string `xml:"Error>Code"`
		}
		_ = xml.Unmarshal(b, &e)
		kind := stsErrorKind(e.Code, resp.StatusCode)
		msg := "AssumeRoleWithWebIdentity refused"
		if e.Code != "" {
			msg += ": " + wire.SafeDetail(e.Code)
		} else {
			msg += ": HTTP " + strconv.Itoa(resp.StatusCode)
		}
		return nil, &apiError{kind: kind, code: e.Code, status: resp.StatusCode, msg: msg, cause: codeError{code: e.Code, status: resp.StatusCode}}
	}
	var r assumeResultXML
	err = xml.NewDecoder(bytes.NewReader(b)).Decode(&r)
	defer r.wipe()
	cr := r.Result.Credentials
	if err != nil || len(cr.AccessKeyID) == 0 || len(cr.SecretAccessKey) == 0 || len(cr.SessionToken) == 0 {
		return nil, &apiError{kind: stores.ErrUnavailable, msg: "cannot decode AssumeRoleWithWebIdentity"}
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(cr.Expiration))
	if err != nil {
		exp = time.Now().Add(dur)
	}
	return &agentCreds{keyID: secret.New(cr.AccessKeyID), secretKey: secret.New(cr.SecretAccessKey), session: secret.New(cr.SessionToken),
		arn: strings.TrimSpace(r.Result.AssumedRoleUser.Arn), expires: exp}, nil
}

// stsErrorKind maps an STS error: a token or trust the role refuses is a
// permission error, an identity provider STS cannot reach is an outage.
func stsErrorKind(code string, status int) error {
	switch code {
	case "AccessDenied", "InvalidIdentityToken", "IDPRejectedClaim", "ExpiredTokenException", "ExpiredToken",
		"MalformedPolicyDocument", "PackedPolicyTooLarge", "RegionDisabledException":
		return stores.ErrPermission
	case "IDPCommunicationError":
		return stores.ErrUnavailable
	}
	kind, _ := classify(code, status)
	return kind
}

// appendQueryEscape percent-encodes b for a form body, keeping AWS's
// unreserved characters.
func appendQueryEscape(dst, b []byte) []byte {
	const hexdig = "0123456789ABCDEF"
	for _, c := range b {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			dst = append(dst, c)
			continue
		}
		dst = append(dst, '%', hexdig[c>>4], hexdig[c&15])
	}
	return dst
}

// AgentCan implements [stores.AgentAccess]: the agent assumes its own role
// with an identity token scrim signs for it, and reads the secret with that
// role (GetSecretValue), so AWS's own IAM decides and CloudTrail records
// the read under the agent's session name. The value read is wiped at
// once. Writes cannot be checked without writing, so they are refused.
func (a *SecretsManager) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead {
		return a.unsupported(op, ref, "AWS cannot check whether the agent's own role may "+string(op)+" without doing it")
	}
	sel, err := a.selectors(op, ref)
	if err != nil {
		return err
	}
	name, err := a.secretName(op, ref)
	if err != nil {
		return err
	}
	c, err := a.agentCredentials(ctx, op, ref, cred)
	if err != nil {
		return err
	}
	defer c.wipe()
	head := map[string]any{"SecretId": name}
	if sel.version != "" {
		head["VersionId"] = sel.version
	}
	if sel.stage != "" {
		head["VersionStage"] = sel.stage
	}
	body, err := jsonBody(head, "", nil, false)
	if err != nil {
		return a.invalid(op, ref, "cannot encode the request")
	}
	b, err := a.c.callWith(ctx, c.provider(), "GetSecretValue", body, false)
	secret.WipeBytes(b)
	if err != nil {
		return a.fail(op, ref, err)
	}
	return nil
}

// AgentCan implements [stores.AgentAccess] like [SecretsManager.AgentCan],
// reading the parameter with GetParameter and decryption, so KMS
// permissions count too.
func (a *ParameterStore) AgentCan(ctx context.Context, cred stores.AgentCredential, op stores.Op, ref stores.Ref) error {
	if op != stores.OpRead {
		return a.unsupported(op, ref, "AWS cannot check whether the agent's own role may "+string(op)+" without doing it")
	}
	name, suffix, err := a.parameter(op, ref)
	if err != nil {
		return err
	}
	c, err := a.agentCredentials(ctx, op, ref, cred)
	if err != nil {
		return err
	}
	defer c.wipe()
	body, err := jsonBody(map[string]any{"Name": name + suffix, "WithDecryption": true}, "", nil, false)
	if err != nil {
		return a.invalid(op, ref, "cannot encode the request")
	}
	b, err := a.c.callWith(ctx, c.provider(), "GetParameter", body, false)
	secret.WipeBytes(b)
	if err != nil {
		return a.fail(op, ref, err)
	}
	return nil
}
