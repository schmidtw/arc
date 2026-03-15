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
package arc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrInvalidSignature is returned when a cryptographic signature verification
// fails during ARC chain validation. Use [errors.Is] to check for this error.
var ErrInvalidSignature = errors.New("invalid signature")

// chainStatus represents the internal validation status of an ARC chain.
type chainStatus string

const (
	chainNone chainStatus = "none"
	chainPass chainStatus = "pass"
	chainFail chainStatus = "fail"
)

// MaxInstance is the maximum number of ARC Sets allowed per message.
const MaxInstance = 50

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
	resolver Resolver
}

// NewValidator creates a new Validator. If no [Resolver] is provided via
// [WithResolver], [net.DefaultResolver] is used.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := Validator{}
	for _, opt := range opts {
		opt.applyValidator(&v)
	}
	if v.resolver == nil {
		v.resolver = net.DefaultResolver
	}
	return &v
}

// Signer adds new ARC Sets to email messages.
type Signer struct {
	key        crypto.Signer
	domain     string
	selector   string
	authServID string
	headers    []HeaderField
	algorithm  string
	hashOpt    crypto.SignerOpts
	timestamp  time.Time
	resolver   Resolver
	validator  *Validator
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
// inferred from the key type (RSA-SHA256 or Ed25519-SHA256).
//
// The domainKey is the DNS domain key FQDN where verifiers look up the
// corresponding public key:
//
//	<selector>._domainkey.<domain>
//
// For example, "2024._domainkey.example.com".
//
// By default, the default signed headers are used, which include common message
// headers (From, To, Subject, Date, etc.). Use [WithSignedHeaders] to override
// this set. If no authentication server ID is set via [WithAuthServID], it
// defaults to the domain. If no resolver is set, [net.DefaultResolver] is used.
func NewSigner(key crypto.Signer, domainKey string, opts ...SignerOption) (*Signer, error) {
	s := Signer{
		key:     key,
		headers: append([]HeaderField{}, defaultSignedHeaders...),
	}
	for _, opt := range opts {
		opt.applySigner(&s)
	}

	// Parse "<selector>._domainkey.<domain>" from the FQDN.
	const marker = "._domainkey."
	idx := strings.Index(domainKey, marker)
	if idx <= 0 {
		return nil, fmt.Errorf("invalid domain key %q: must be in the form <selector>._domainkey.<domain>", domainKey)
	}
	s.selector = domainKey[:idx]
	s.domain = domainKey[idx+len(marker):]
	if s.domain == "" {
		return nil, fmt.Errorf("invalid domain key %q: domain is empty", domainKey)
	}

	if s.authServID == "" {
		s.authServID = s.domain
	}
	if s.resolver == nil {
		s.resolver = net.DefaultResolver
	}
	s.validator = NewValidator(WithResolver(s.resolver))

	// Infer algorithm from key type.
	algo, hashOpt, err := algorithmForKey(key)
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
func WithAuthServID(id string) SignerOption {
	return signerOptionFunc(func(s *Signer) {
		s.authServID = id
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
