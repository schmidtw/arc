// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"bytes"
	"container/list"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Validate validates the ARC chain on the given message. It returns whether
// an ARC chain was present (true) or absent (false). If the chain is present
// but invalid, it returns true and a non-nil error describing the failure.
func (v *Validator) Validate(ctx context.Context, message io.Reader) (bool, error) {
	msg, err := parseMessage(message)
	if err != nil {
		return false, fmt.Errorf("parsing message: %w", err)
	}

	status, err := v.validateMessage(ctx, msg)
	if status == chainNone {
		return false, nil
	}
	return true, err
}

// ValidateBytes validates the ARC chain on the given raw message bytes.
func (v *Validator) ValidateBytes(ctx context.Context, message []byte) (bool, error) {
	return v.Validate(ctx, bytes.NewReader(message))
}

func (v *Validator) validateMessage(ctx context.Context, msg *message) (chainStatus, error) {
	sets, err := collectArcSets(msg)
	if err != nil {
		return chainFail, fmt.Errorf("collecting ARC sets: %w", err)
	}

	// Step 1: No ARC sets = none.
	if len(sets) == 0 {
		return chainNone, nil
	}

	n := len(sets)

	// Step 1: Check max instance limit.
	if n > v.maxArcSets {
		return chainFail, fmt.Errorf("instance count %d exceeds maximum %d", n, v.maxArcSets)
	}

	// Step 2: If the highest instance is already marked as failing, result is fail.
	highest := sets[n-1]
	if highest.Seal == nil {
		return chainFail, fmt.Errorf("highest instance %d missing ARC-Seal", highest.Instance)
	}
	if highest.Seal.ChainValidation == chainFail {
		return chainFail, fmt.Errorf("highest instance %d has cv=fail", highest.Instance)
	}

	// Step 3: Validate chain structure.
	if err := validateStructure(sets); err != nil {
		return chainFail, err
	}

	// Step 4: Validate the ARC-Message-Signature at the highest instance.
	if err := v.verifyAMS(ctx, msg, highest.AMS); err != nil {
		return chainFail, err
	}

	// Step 5: Validate each ARC-Seal from highest to lowest.
	for i := n - 1; i >= 0; i-- {
		if err := v.verifyAS(ctx, msg, sets, i); err != nil {
			return chainFail, err
		}
	}

	return chainPass, nil
}

// validateStructure checks that ARC sets form a valid chain: contiguous
// instance numbers, all three headers present, and correct chain status values.
func validateStructure(sets []*arcSet) error {
	for i, s := range sets {
		expectedInstance := i + 1
		if s.Instance != expectedInstance {
			return fmt.Errorf("instance gap: expected %d, got %d", expectedInstance, s.Instance)
		}
		if s.AAR == nil {
			return fmt.Errorf("instance %d missing AAR", s.Instance)
		}
		if s.AMS == nil {
			return fmt.Errorf("instance %d missing AMS", s.Instance)
		}
		if s.Seal == nil {
			return fmt.Errorf("instance %d missing AS", s.Instance)
		}

		// Check chain validation status values.
		if s.Instance == 1 {
			if s.Seal.ChainValidation != chainNone {
				return fmt.Errorf("instance 1 cv must be 'none', got %q", s.Seal.ChainValidation)
			}
		} else {
			if s.Seal.ChainValidation != chainPass {
				return fmt.Errorf("instance %d cv must be 'pass', got %q", s.Instance, s.Seal.ChainValidation)
			}
		}
	}
	return nil
}

// buildVerifier creates a verifyFunc for the given public key.
func (v *Validator) buildVerifier(key crypto.PublicKey, domainKey string) (verifyFunc, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < v.minBits {
			return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d)", k.N.BitLen(), v.minBits)
		}
		return func(algorithm string, data, signature []byte) error {
			if algorithm != algRSASHA256 {
				return fmt.Errorf("algorithm mismatch: expected %s, got %s", algRSASHA256, algorithm)
			}
			hash := sha256.Sum256(data)
			if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], signature); err != nil {
				return errors.Join(ErrInvalidSignature, err)
			}
			return nil
		}, nil
	case ed25519.PublicKey:
		return func(algorithm string, data, signature []byte) error {
			if algorithm != algEd25519SHA256 {
				return fmt.Errorf("algorithm mismatch: expected %s, got %s", algEd25519SHA256, algorithm)
			}
			hash := sha256.Sum256(data)
			if !ed25519.Verify(k, hash[:], signature) {
				return errors.Join(ErrInvalidSignature,
					fmt.Errorf("ed25519 signature verification failed"))
			}
			return nil
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T for %q", key, domainKey)
	}
}

// evictLRU removes the least recently used cache entry if at capacity.
func (v *Validator) evictLRU() {
	if v.maxCacheSize > 0 && len(v.sigCache) >= v.maxCacheSize {
		if elem := v.cacheList.Back(); elem != nil {
			entry := elem.Value.(*cacheEntry)
			delete(v.sigCache, entry.key)
			v.cacheList.Remove(elem)
		}
	}
}

// cacheAdd adds a new entry to the cache with LRU tracking.
// Note: We don't store or respect DNS TTL because net.Resolver doesn't expose it.
// Entries are evicted by LRU policy or when content changes (detected on lookup).
func (v *Validator) cacheAdd(domainKey, record string, verify verifyFunc) {
	// Skip caching if disabled.
	if v.maxCacheSize == 0 {
		return
	}

	v.evictLRU()

	var element *list.Element
	if v.maxCacheSize > 0 {
		element = v.cacheList.PushFront(&cacheEntry{key: domainKey})
	}

	v.sigCache[domainKey] = txtKey{
		txt:     record,
		verify:  verify,
		element: element,
	}
}

// checkCache checks if a cached verifier exists for the given domain key and record.
// Returns the cached verifier if found and still valid, nil otherwise.
// Must be called with caching enabled (maxCacheSize != 0).
//
// Cache invalidation is content-based rather than TTL-based: if the DNS record
// content has changed since caching, the old entry is removed and nil is returned.
// This detects key rotations but not TTL expirations.
func (v *Validator) checkCache(domainKey, record string) verifyFunc {
	v.m.Lock()
	defer v.m.Unlock()

	cached, ok := v.sigCache[domainKey]
	if !ok {
		return nil
	}

	if cached.txt != record {
		// Record changed since last lookup. Remove stale entry.
		if cached.element != nil {
			v.cacheList.Remove(cached.element)
		}
		delete(v.sigCache, domainKey)
		return nil
	}

	// Cache hit: move to front (most recently used).
	if cached.element != nil {
		v.cacheList.MoveToFront(cached.element)
	}
	return cached.verify
}

// storeInCache stores a verifier in the cache with double-check for race conditions.
// Returns the verifier to use (either the newly stored one or one from another goroutine).
// Must be called with caching enabled (maxCacheSize != 0).
func (v *Validator) storeInCache(domainKey, record string, verify verifyFunc) verifyFunc {
	v.m.Lock()
	defer v.m.Unlock()

	// Double-check: another goroutine may have cached this while we were building.
	if cached, ok := v.sigCache[domainKey]; ok {
		if cached.txt == record {
			// Use the already-cached result.
			if cached.element != nil {
				v.cacheList.MoveToFront(cached.element)
			}
			return cached.verify
		}
		// DNS record changed; remove old entry before adding new one.
		if cached.element != nil {
			v.cacheList.Remove(cached.element)
		}
		delete(v.sigCache, domainKey)
	}

	v.cacheAdd(domainKey, record, verify)
	return verify
}

// lookupKey retrieves a verification function for the given domain and selector
// via DNS TXT record lookup.
func (v *Validator) lookupKey(ctx context.Context, domain, selector string) (verifyFunc, error) {
	domainKey := makeDomainkey(selector, domain)

	// Perform DNS lookup.
	records, err := v.resolver.LookupTXT(ctx, domainKey)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup for %q: %w", domainKey, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no TXT records found for %q", domainKey)
	}
	record := strings.Join(records, "")

	// Check cache if enabled.
	if v.maxCacheSize != 0 {
		if cached := v.checkCache(domainKey, record); cached != nil {
			return cached, nil
		}
	}

	// Parse and build verifier outside lock to reduce contention.
	key, err := parseKeyRecord(record)
	if err != nil {
		return nil, fmt.Errorf("parsing key record for %q: %w", domainKey, err)
	}

	verify, err := v.buildVerifier(key, domainKey)
	if err != nil {
		return nil, err
	}

	// Store in cache if enabled.
	if v.maxCacheSize != 0 {
		verify = v.storeInCache(domainKey, record, verify)
	}

	return verify, nil
}

// verifyAMS verifies an ARC-Message-Signature by checking the body hash
// and verifying the cryptographic signature against the DNS public key.
func (v *Validator) verifyAMS(ctx context.Context, msg *message, ams *ams) error {
	// Look up the public key.
	verify, err := v.lookupKey(ctx, ams.Domain, ams.Selector)
	if err != nil {
		return fmt.Errorf("key lookup for AMS i=%d: %w", ams.Instance, err)
	}

	// Verify body hash.
	bodyHash := computeBodyHash(msg.Body)
	if !bytes.Equal(bodyHash, ams.BodyHash) {
		return fmt.Errorf("AMS i=%d body hash mismatch", ams.Instance)
	}

	// Build the data to verify: canonicalized signed headers + the AMS header.
	data := buildAMSSignedData(msg, ams)

	return verify(ams.Algorithm, data, ams.Signature)
}

// buildAMSSignedData builds the data that was signed by the ARC-Message-Signature.
// Headers are hashed in the order listed in the signed headers list, with
// each header found bottom-up in the message.
func buildAMSSignedData(msg *message, ams *ams) []byte {
	var buf bytes.Buffer

	// Track which header instances have been consumed (bottom-up search).
	used := make(map[int]bool)

	// For each header name in the signed headers list:
	for _, hName := range ams.Headers {
		hNameLower := strings.ToLower(hName)
		// Find the bottom-most unused occurrence.
		for i := len(msg.Headers) - 1; i >= 0; i-- {
			if used[i] {
				continue
			}
			if strings.ToLower(msg.Headers[i].Key) == hNameLower {
				used[i] = true
				canon := canonicalizeHeaderRelaxed(msg.Headers[i].Key, msg.Headers[i].Value)
				buf.WriteString(canon)
				buf.WriteString("\r\n")
				break
			}
		}
	}

	// Add the AMS header with its signature value removed.
	amsForSigning := removeSignatureFromHeader("ARC-Message-Signature", ams.Raw)
	canon := canonicalizeHeaderRelaxedRaw(amsForSigning)
	buf.WriteString(canon)

	return buf.Bytes()
}

// verifyAS verifies the ARC-Seal at the given set index.
func (v *Validator) verifyAS(ctx context.Context, msg *message, sets []*arcSet, idx int) error {
	as := sets[idx].Seal

	verify, err := v.lookupKey(ctx, as.Domain, as.Selector)
	if err != nil {
		return fmt.Errorf("key lookup for AS i=%d: %w", as.Instance, err)
	}

	data := buildASSignedData(msg, sets, idx)

	return verify(as.Algorithm, data, as.Signature)
}

// buildASSignedData builds the data that was signed by the ARC-Seal at index idx.
// Headers are processed within each ARC Set in order (AAR, AMS, AS) for each
// instance from 1 to K. The ARC-Seal for instance K has its signature emptied.
func buildASSignedData(msg *message, sets []*arcSet, idx int) []byte {
	var buf bytes.Buffer

	k := idx + 1 // instance number (1-based)

	for i := 0; i < k; i++ {
		// AAR for this instance.
		canon := canonicalizeHeaderRelaxedRaw(sets[i].AAR.Raw)
		buf.WriteString(canon)
		buf.WriteString("\r\n")

		// AMS for this instance.
		canon = canonicalizeHeaderRelaxedRaw(sets[i].AMS.Raw)
		buf.WriteString(canon)
		buf.WriteString("\r\n")

		// ARC-Seal for this instance.
		if i < k-1 {
			// Previous instance: use full ARC-Seal.
			canon = canonicalizeHeaderRelaxedRaw(sets[i].Seal.Raw)
			buf.WriteString(canon)
			buf.WriteString("\r\n")
		} else {
			// Current instance: ARC-Seal with signature emptied (no trailing CRLF).
			asForSigning := removeSignatureFromHeader("ARC-Seal", sets[i].Seal.Raw)
			canon = canonicalizeHeaderRelaxedRaw(asForSigning)
			buf.WriteString(canon)
		}
	}

	return buf.Bytes()
}

// removeSignatureFromHeader removes the signature value from a header,
// keeping the tag name but emptying its value (for signature computation).
func removeSignatureFromHeader(name, raw string) string {
	// Handle raw that may or may not start with the header name.
	fullHeader := raw
	if !strings.HasPrefix(strings.ToLower(raw), strings.ToLower(name)+":") {
		fullHeader = name + ":" + raw
	}

	// Find the signature tag and empty its value.
	// Handle folded headers by unfolding first.
	unfolded := strings.ReplaceAll(fullHeader, "\r\n", "")
	unfolded = strings.ReplaceAll(unfolded, "\n", "")

	// Find "b=" (the signature tag, not "bh=" the body hash tag).
	result := removeBTag(unfolded)
	return result
}

// removeBTag removes the signature value from a header string.
// It targets the b= tag specifically, not the bh= (body hash) tag.
func removeBTag(s string) string {
	// Split on semicolons to find the signature tag.
	parts := strings.Split(s, ";")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "b=") && !strings.HasPrefix(trimmed, "bh=") {
			// Find where in the original part the "b=" starts.
			bIdx := strings.Index(part, "b=")
			parts[i] = part[:bIdx] + "b="
		}
	}
	return strings.Join(parts, ";")
}
