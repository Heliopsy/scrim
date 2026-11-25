// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Revocation scopes (identity.client-certificates.revocation-scope).
const (
	// RevocationEndEntity checks the client certificate only.
	RevocationEndEntity = "end-entity"
	// RevocationChain checks every certificate below the trust anchor.
	RevocationChain = "chain"
)

// What an OCSP check does when it gets no valid answer
// (identity.client-certificates.ocsp.unreachable).
const (
	// OCSPFailClosed refuses the certificate.
	OCSPFailClosed = "fail-closed"
	// OCSPSoftFail accepts it as if OCSP were off.
	OCSPSoftFail = "soft-fail"
)

// MaxOCSPTimeout bounds identity.client-certificates.ocsp.timeout, so the
// data plane's wait for a check always outlasts the check.
const MaxOCSPTimeout = 10 * time.Second

const (
	// ocspResponseMax bounds a responder's answer; real ones are a few
	// kilobytes.
	ocspResponseMax = 64 << 10
	// ocspNoNextUpdate is how long a response without a next update counts
	// as current after it was produced (RFC 5019 requires one, not every
	// responder sends it).
	ocspNoNextUpdate = time.Hour
	// ocspSkew is the clock skew allowed on a response's thisUpdate.
	ocspSkew = 5 * time.Minute
)

// OCSPStatus is what an OCSP check found out about one certificate.
type OCSPStatus int

// OCSP check outcomes.
const (
	// OCSPUnavailable means no valid answer: the responder could not be
	// reached, answered with an error, or sent a response that does not
	// verify or is stale.
	OCSPUnavailable OCSPStatus = iota
	// OCSPGood is a current, verified "good" answer.
	OCSPGood
	// OCSPRevoked is a current, verified "revoked" answer.
	OCSPRevoked
	// OCSPUnknown is a current, verified "unknown" answer: the responder
	// does not know the certificate.
	OCSPUnknown
)

func (s OCSPStatus) String() string {
	switch s {
	case OCSPGood:
		return "good"
	case OCSPRevoked:
		return "revoked"
	case OCSPUnknown:
		return "unknown"
	default:
		return "unavailable"
	}
}

// OCSPChecker asks OCSP responders about client certificates and keeps
// verified answers until their next update, in a bounded cache. Everything
// it handles is public.
type OCSPChecker struct {
	// Responder, when set, is asked about every certificate instead of the
	// one in the certificate's authority information access extension.
	Responder string
	// SoftFail accepts a certificate when no valid answer can be had.
	SoftFail bool
	// Timeout bounds one request; zero means MaxOCSPTimeout.
	Timeout time.Duration
	// CacheSize bounds the cache; zero means 10000.
	CacheSize int
	// Client sends the requests; nil uses a client over a clone of
	// http.DefaultTransport, which follows the upstream proxy
	// (internal/netproxy).
	Client *http.Client
	// Log receives a warning for every check without a valid answer.
	Log *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	once     sync.Once
	client   *http.Client
	mu       sync.Mutex
	cache    map[ocspKey]ocspEntry
	inflight map[ocspKey]*ocspCall
}

// ocspKey names one certificate: its issuer's key and its serial number.
type ocspKey struct {
	issuer [sha256.Size]byte
	serial string
}

type ocspEntry struct {
	status  OCSPStatus
	expires time.Time
}

type ocspCall struct {
	done   chan struct{}
	status OCSPStatus
}

// ResponderFor is the responder asked about c: the configured one, else the
// first http or https URL of c's authority information access, else "".
func (o *OCSPChecker) ResponderFor(c *x509.Certificate) string {
	if o.Responder != "" {
		return o.Responder
	}
	for _, s := range c.OCSPServer {
		if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			return s
		}
	}
	return ""
}

func (o *OCSPChecker) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OCSPChecker) init() {
	o.once.Do(func() {
		o.client = o.Client
		if o.client == nil {
			o.client = &http.Client{Transport: http.DefaultTransport}
			if t, ok := http.DefaultTransport.(*http.Transport); ok {
				o.client.Transport = t.Clone()
			}
		}
		o.cache = map[ocspKey]ocspEntry{}
		o.inflight = map[ocspKey]*ocspCall{}
	})
}

// Check returns c's status from the cache or from its responder. Concurrent
// checks of one certificate share one request. A certificate without a
// responder is OCSPUnavailable; callers check [OCSPChecker.ResponderFor]
// first.
func (o *OCSPChecker) Check(ctx context.Context, c, issuer *x509.Certificate) OCSPStatus {
	o.init()
	key := ocspKey{issuer: sha256.Sum256(issuer.RawSubjectPublicKeyInfo), serial: string(c.SerialNumber.Bytes())}
	o.mu.Lock()
	if e, ok := o.cache[key]; ok {
		if o.now().Before(e.expires) {
			o.mu.Unlock()
			return e.status
		}
		delete(o.cache, key)
	}
	if call, ok := o.inflight[key]; ok {
		o.mu.Unlock()
		select {
		case <-call.done:
			return call.status
		case <-ctx.Done():
			return OCSPUnavailable
		}
	}
	call := &ocspCall{done: make(chan struct{})}
	o.inflight[key] = call
	o.mu.Unlock()

	status, expires, err := o.fetch(ctx, c, issuer)
	if err != nil && o.Log != nil {
		o.Log.Warn("no valid OCSP answer for a client certificate", "serial", c.SerialNumber.Text(16),
			"subject", c.Subject.String(), "responder", o.ResponderFor(c), "err", err)
	}
	o.mu.Lock()
	delete(o.inflight, key)
	if status != OCSPUnavailable && o.now().Before(expires) {
		o.store(key, ocspEntry{status: status, expires: expires})
	}
	o.mu.Unlock()
	call.status = status
	close(call.done)
	return status
}

// store adds e, making room first: expired entries go, then the ones that
// expire soonest. Called with mu held.
func (o *OCSPChecker) store(key ocspKey, e ocspEntry) {
	limit := o.CacheSize
	if limit <= 0 {
		limit = 10000
	}
	if len(o.cache) >= limit {
		now := o.now()
		for k, v := range o.cache {
			if !now.Before(v.expires) {
				delete(o.cache, k)
			}
		}
	}
	for len(o.cache) >= limit {
		var victim ocspKey
		first := true
		var soonest time.Time
		for k, v := range o.cache {
			if first || v.expires.Before(soonest) {
				victim, soonest, first = k, v.expires, false
			}
		}
		delete(o.cache, victim)
	}
	o.cache[key] = e
}

// CacheLen is how many answers the cache holds.
func (o *OCSPChecker) CacheLen() int {
	o.init()
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.cache)
}

// fetch asks the responder about c and verifies the answer: signed by
// issuer or by a responder issuer delegated to (OCSP signing usage), for c's
// serial number, produced no later than now and current. It returns the
// status and until when it may be kept.
func (o *OCSPChecker) fetch(ctx context.Context, c, issuer *x509.Certificate) (OCSPStatus, time.Time, error) {
	responder := o.ResponderFor(c)
	if responder == "" {
		return OCSPUnavailable, time.Time{}, errors.New("the certificate names no OCSP responder")
	}
	req, err := ocsp.CreateRequest(c, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("building the request: %w", err)
	}
	timeout := o.Timeout
	if timeout <= 0 || timeout > MaxOCSPTimeout {
		timeout = MaxOCSPTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, responder, bytes.NewReader(req))
	if err != nil {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("building the request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/ocsp-request")
	hreq.Header.Set("Accept", "application/ocsp-response")
	resp, err := o.client.Do(hreq)
	if err != nil {
		return OCSPUnavailable, time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("responder answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ocspResponseMax+1))
	if err != nil {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("reading the response: %w", err)
	}
	if len(body) > ocspResponseMax {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("response is larger than %d bytes", ocspResponseMax)
	}
	return verifyOCSP(body, c, issuer, o.now())
}

// verifyOCSP checks a DER OCSP response about c and returns its status and
// until when it is current.
func verifyOCSP(der []byte, c, issuer *x509.Certificate, now time.Time) (OCSPStatus, time.Time, error) {
	// Without an issuer the parser checks only that an embedded responder
	// certificate signed the response; who may sign is checked below.
	r, err := ocsp.ParseResponseForCert(der, c, nil)
	if err != nil {
		return OCSPUnavailable, time.Time{}, fmt.Errorf("response: %w", err)
	}
	switch {
	case r.Certificate == nil || bytes.Equal(r.Certificate.Raw, issuer.Raw):
		if err := r.CheckSignatureFrom(issuer); err != nil {
			return OCSPUnavailable, time.Time{}, fmt.Errorf("response is not signed by the issuer: %w", err)
		}
	default:
		d := r.Certificate
		if err := d.CheckSignatureFrom(issuer); err != nil {
			return OCSPUnavailable, time.Time{}, fmt.Errorf("responder certificate is not issued by the certificate's issuer: %w", err)
		}
		if !slices.Contains(d.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
			return OCSPUnavailable, time.Time{}, errors.New("responder certificate is not for OCSP signing")
		}
		if now.Before(d.NotBefore) || now.After(d.NotAfter) {
			return OCSPUnavailable, time.Time{}, errors.New("responder certificate is outside its validity period")
		}
	}
	if r.ThisUpdate.After(now.Add(ocspSkew)) {
		return OCSPUnavailable, time.Time{}, errors.New("response is from the future")
	}
	expires := r.NextUpdate
	if expires.IsZero() {
		expires = r.ThisUpdate.Add(ocspNoNextUpdate)
	}
	if !now.Before(expires) {
		return OCSPUnavailable, time.Time{}, errors.New("response is past its next update")
	}
	switch r.Status {
	case ocsp.Good:
		return OCSPGood, expires, nil
	case ocsp.Revoked:
		return OCSPRevoked, expires, nil
	case ocsp.Unknown:
		return OCSPUnknown, expires, nil
	default:
		return OCSPUnavailable, time.Time{}, fmt.Errorf("unexpected status %d", r.Status)
	}
}

// String describes the checker's settings, for logs.
func (o *OCSPChecker) String() string {
	if o == nil {
		return "off"
	}
	var b strings.Builder
	b.WriteString("on")
	if o.Responder != "" {
		b.WriteString(", responder ")
		b.WriteString(o.Responder)
	}
	if o.SoftFail {
		b.WriteString(", soft-fail")
	}
	return b.String()
}
