// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package arc implements RFC 8617, the Authenticated Received Chain (ARC) protocol.
//
// ARC provides an authenticated "chain of custody" for email messages,
// allowing each entity that handles the message to see what entities
// handled it before and what the message's authentication assessment
// was at each step.
//
// # Validating an ARC Chain
//
// To validate an ARC chain on an incoming message:
//
//	import (
//		"context"
//		"io"
//		"github.com/schmidtw/arc"
//	)
//
//	func validateMessage(message io.Reader) error {
//		v := arc.NewValidator() // uses net.DefaultResolver
//		present, err := v.Validate(context.Background(), message)
//		if err != nil {
//			return err // chain validation failed
//		}
//		if !present {
//			// No ARC headers present
//		}
//		// ARC chain validated successfully
//		return nil
//	}
//
// # Signing a Message (Creating a New ARC Set)
//
// To add an ARC Set to a message:
//
//	import (
//		"context"
//		"crypto"
//		"github.com/schmidtw/arc"
//	)
//
//	func signMessage(message []byte, privateKey crypto.Signer) ([]byte, error) {
//		signer, err := arc.NewSigner(privateKey, "sel._domainkey.example.org")
//		if err != nil {
//			return nil, err
//		}
//
//		return signer.SignBytes(context.Background(), message, "spf=pass; dkim=pass")
//	}
//
// The Sign method validates any existing ARC chain before adding a new set.
// If validation succeeds, the new set is marked as passing. If validation
// fails, the new set is marked as failing. Signing is refused if the most
// recent set in the chain was already marked as failing.
//
// To customize validation behavior, provide a validator via [WithValidator]:
//
//	validator := arc.NewValidator(arc.WithMinRSAKeyBits(2048))
//	signer, err := arc.NewSigner(privateKey, "sel._domainkey.example.org",
//		arc.WithValidator(validator))
package arc

import (
	"container/list"
	"context"
	"crypto"
	"errors"
	"net"
	"sync"
	"time"
)

// ErrInvalidSignature is returned when a cryptographic signature verification
// fails during ARC chain validation. Use [errors.Is] to check for this error.
var ErrInvalidSignature = errors.New("invalid signature")

// ErrRSAKeyTooSmall is returned when an RSA key is smaller than the configured
// minimum size during validation or signing. Use [errors.Is] to check for this error.
var ErrRSAKeyTooSmall = errors.New("RSA key size is too small")

// chainStatus represents the internal validation status of an ARC chain.
type chainStatus string

const (
	chainNone chainStatus = "none"
	chainPass chainStatus = "pass"
	chainFail chainStatus = "fail"
)

// aar represents a parsed ARC-Authentication-Results header field.
type aar struct {
	Instance   int    // Instance number (1-50)
	Raw        string // The complete raw header field value
	AuthServID string // The authserv-id
	Results    string // The authentication results payload
}

// ams represents a parsed ARC-Message-Signature header field.
type ams struct {
	Instance  int       // Instance number (1-50)
	Algorithm string    // Signing algorithm (a= tag)
	Signature []byte    // Decoded signature (b= tag)
	BodyHash  []byte    // Decoded body hash (bh= tag)
	Domain    string    // Signing domain (d= tag)
	Headers   []string  // Signed header fields (h= tag)
	Selector  string    // Key selector (s= tag)
	Timestamp time.Time // Signature timestamp (t= tag)
	Raw       string    // The complete raw header field value
}

// arcSeal represents a parsed ARC-Seal header field.
type arcSeal struct {
	Instance        int         // Instance number (1-50)
	Algorithm       string      // Signing algorithm (a= tag)
	Signature       []byte      // Decoded signature (b= tag)
	ChainValidation chainStatus // Chain validation status (cv= tag)
	Domain          string      // Signing domain (d= tag)
	Selector        string      // Key selector (s= tag)
	Timestamp       time.Time   // Signature timestamp (t= tag)
	Raw             string      // The complete raw header field value
}

// arcSet groups the three ARC header fields that share the same instance number.
type arcSet struct {
	Instance int      // The shared instance number
	AAR      *aar     // ARC-Authentication-Results
	AMS      *ams     // ARC-Message-Signature
	Seal     *arcSeal // ARC-Seal
}

// Resolver looks up DNS TXT records. The standard library's [*net.Resolver]
// satisfies this interface.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// ValidatorOption configures a [Validator].
type ValidatorOption interface {
	applyValidator(*Validator)
}

// Validator validates ARC chains on email messages.
type Validator struct {
	resolver     Resolver
	minBits      int
	maxArcSets   int
	maxCacheSize int
	sigCache     map[string]txtKey
	cacheList    *list.List
	m            sync.Mutex
}

type verifyFunc func(algorithm string, data, signature []byte) error

type txtKey struct {
	txt     string
	verify  verifyFunc
	element *list.Element
}

type cacheEntry struct {
	key string
}

// NewValidator creates a new Validator. If no [Resolver] is provided via
// [WithResolver], [net.DefaultResolver] is used.  By default, the minimum
// accepted RSA key size is 1024 bits. Use [WithMinRSAKeyBits] to override.
//
// The DNS key cache is bounded by default to 1000 entries using LRU eviction.
// Use [WithMaxCacheSize] to adjust the limit or disable caching.
//
// The maximum number of ARC Sets is fixed at 50 per RFC 8617. The RFC defines
// instance values (i=) as ranging from 1 to 50, making this an absolute limit
// in the protocol specification.
func NewValidator(opts ...ValidatorOption) (*Validator, error) {
	v := Validator{
		sigCache:   make(map[string]txtKey),
		cacheList:  list.New(),
		maxArcSets: 50, // Fixed per RFC 8617 - instance values range from 1 to 50.
	}

	defaults := []ValidatorOption{ // nolint:prealloc
		WithMinRSAKeyBits(1024),
		WithResolver(net.DefaultResolver),
		WithMaxCacheSize(1000),
	}
	opts = append(defaults, opts...)

	for _, opt := range opts {
		opt.applyValidator(&v)
	}

	if v.minBits < 1024 {
		return nil, ErrRSAKeyTooSmall
	}

	return &v, nil
}

// Signer adds new ARC Sets to email messages.
type Signer struct {
	key           crypto.Signer
	domain        string
	selector      string
	authServID    string
	headers       []HeaderField
	algorithm     string
	maxArcSets    int
	minSignerBits int
	hashOpt       crypto.SignerOpts
	timestamp     time.Time
	resolver      Resolver
	validator     *Validator
}

// SignerOption configures a [Signer].
type SignerOption interface {
	applySigner(*Signer)
}

// signerOptionFunc adapts a function to the SignerOption interface.
type signerOptionFunc func(*Signer)

func (f signerOptionFunc) applySigner(s *Signer) { f(s) }

// NewSigner creates a new Signer with the given key and domain key FQDN.
//
// The key is the private key used for signing. The signing algorithm is
// inferred from the key type (RSA or Ed25519).
//
// The domainKey is the DNS domain key FQDN where verifiers look up the
// corresponding public key:
//
//	<selector>._domainkey.<domain>
//
// For example, "2024._domainkey.example.com".
//
// A validator is used to validate existing ARC chains before adding a new set.
// This determines whether the new ARC-Seal will have cv=pass or cv=fail.
// If no validator is provided via [WithValidator], a default validator with
// standard settings is created.
//
// By default, the default signed headers are used, which include common message
// headers (From, To, Subject, Date, etc.). Use [WithSignedHeaders] to override
// this set. If no authentication server ID is set via [WithAuthServID], it
// defaults to the domain. If no resolver is set, [net.DefaultResolver] is used.
//
// The maximum number of ARC Sets is fixed at 50 per RFC 8617. The RFC defines
// instance values (i=) as ranging from 1 to 50, making this an absolute limit
// in the protocol specification.
func NewSigner(key crypto.Signer, domainKey string, opts ...SignerOption) (*Signer, error) {
	s := Signer{
		key:        key,
		maxArcSets: 50, // Fixed per RFC 8617 - instance values range from 1 to 50.
	}

	defaults := []SignerOption{ // nolint:prealloc
		WithSignedHeaders(defaultSignedHeaders...),
		WithResolver(net.DefaultResolver),
		WithMinRSAKeyBits(2048),
	}
	opts = append(defaults, opts...)

	for _, opt := range opts {
		opt.applySigner(&s)
	}

	if s.minSignerBits < 1024 {
		return nil, ErrRSAKeyTooSmall
	}

	// Parse "<selector>._domainkey.<domain>" from the FQDN.
	var err error
	s.selector, s.domain, err = splitDomainkey(domainKey)
	if err != nil {
		return nil, err
	}

	if s.authServID == "" {
		s.authServID = s.domain
	}

	// Create a default validator if none was provided.
	if s.validator == nil {
		var err error
		s.validator, err = NewValidator(WithResolver(s.resolver))
		if err != nil {
			return nil, err
		}
	}

	// Infer algorithm from key type and validate key size.
	// Per RFC 8301, signers SHOULD use at least 2048 bits for RSA keys.
	algo, hashOpt, err := algorithmForKey(key, s.minSignerBits)
	if err != nil {
		return nil, err
	}
	s.algorithm = algo
	s.hashOpt = hashOpt

	return &s, nil
}

// WithSignedHeaders sets the message header fields whose values will be
// covered by the ARC-Message-Signature. Use the [HeaderField] constants
// for standard fields, or convert custom header names:
// HeaderField("X-Custom-Header").
func WithSignedHeaders(headers ...HeaderField) SignerOption {
	return signerOptionFunc(func(s *Signer) {
		s.headers = headers
	})
}

// WithTimestamp sets a fixed signing timestamp. If not set or zero,
// the current time is used at signing time.
func WithTimestamp(ts time.Time) SignerOption {
	return signerOptionFunc(func(s *Signer) {
		s.timestamp = ts
	})
}

// WithAuthServID sets the authentication server identifier for the
// ARC-Authentication-Results header. This identifies the organization
// that performed authentication checks on the message.
// If not set, defaults to the signing domain.
//
// See https://www.rfc-editor.org/rfc/rfc8601#section-2.5 for guidance
// on choosing an appropriate value.
func WithAuthServID(id string) SignerOption {
	return signerOptionFunc(func(s *Signer) {
		s.authServID = id
	})
}

// WithValidator sets a custom [Validator] for the signer to use when
// validating existing ARC chains before adding a new set.
//
// If not provided, a default validator is created with:
//   - [net.DefaultResolver] for DNS lookups
//   - 1024-bit minimum RSA key size (per RFC 8301)
//   - 50 maximum ARC sets
//
// You can create a custom validator to control validation behavior:
//
//	v := arc.NewValidator(
//	    arc.WithMinRSAKeyBits(2048),
//	    arc.WithResolver(customResolver),
//	)
//	signer, err := arc.NewSigner(key, domainKey, arc.WithValidator(v))
func WithValidator(v *Validator) SignerOption {
	return signerOptionFunc(func(s *Signer) {
		s.validator = v
	})
}

// Option is an option that can be passed to both [NewValidator] and [NewSigner].
type Option interface {
	SignerOption
	ValidatorOption
}

// resolverOption implements [Option].
type resolverOption struct {
	resolver Resolver
}

func (o resolverOption) applySigner(s *Signer)       { s.resolver = o.resolver }
func (o resolverOption) applyValidator(v *Validator) { v.resolver = o.resolver }

// WithResolver sets a custom [Resolver] for DNS TXT record lookups.
// If not set, [net.DefaultResolver] is used. This option can be passed
// to both [NewValidator] and [NewSigner].
func WithResolver(r Resolver) Option {
	return resolverOption{resolver: r}
}

type minRSAKeyBits struct {
	bits int
}

func (o minRSAKeyBits) applyValidator(v *Validator) {
	v.minBits = o.bits
}

func (o minRSAKeyBits) applySigner(s *Signer) {
	s.minSignerBits = o.bits
}

// WithMinRSAKeyBits sets the minimum accepted RSA key size in bits.
// This option can be passed to both [NewValidator] and [NewSigner].
//
// For validators, this controls the minimum key size accepted when validating
// other parties' signatures. Default is 1024 bits per RFC 8301 (which updates
// RFC 6376 Section 3.3.3): verifiers MUST accept 1024-bit to 4096-bit keys.
//
// For signers, this controls the minimum key size for the signer's own private
// key. Default is 2048 bits per RFC 8301, which states that signers SHOULD use
// at least 2048 bits.
//
// Values less than 1024 result in an error.
//
// See https://www.rfc-editor.org/rfc/rfc8301 and
// https://www.rfc-editor.org/rfc/rfc6376#section-3.3.3 for details.
func WithMinRSAKeyBits(bits int) Option {
	return minRSAKeyBits{bits: bits}
}

type maxCacheSize struct {
	size int
}

func (o maxCacheSize) applyValidator(v *Validator) {
	v.maxCacheSize = o.size
}

// WithMaxCacheSize sets the maximum number of DNS public keys to cache.
// This option can be passed to [NewValidator].
//
// The cache uses LRU (Least Recently Used) eviction when the limit is reached.
// Set to 0 to disable caching entirely. Set to -1 for unlimited cache size
// (not recommended for long-running services).
//
// Default is 1000 entries, which should be sufficient for most use cases while
// preventing unbounded memory growth in long-running validators.
func WithMaxCacheSize(size int) ValidatorOption {
	if size < 0 {
		size = -1
	}
	return maxCacheSize{size: size}
}
