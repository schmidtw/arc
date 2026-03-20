// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCacheResolver is a resolver that tracks lookup calls and can return different keys.
type testCacheResolver struct {
	mu      sync.Mutex
	lookups map[string]int // track number of lookups per domain
	records map[string]string
}

func newTestCacheResolver() *testCacheResolver {
	return &testCacheResolver{
		lookups: make(map[string]int),
		records: make(map[string]string),
	}
}

func (r *testCacheResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lookups[name]++
	if record, ok := r.records[name]; ok {
		return []string{record}, nil
	}
	return nil, fmt.Errorf("no record found for %s", name)
}

func (r *testCacheResolver) setRecord(name, record string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[name] = record
}

func (r *testCacheResolver) getLookupCount(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups[name]
}

const testDomainKey = "sel._domainkey.example.com"

// generateTestKeyRecord creates a valid DKIM key record for testing.
func generateTestKeyRecord(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create a DKIM key record with the public key
	record := fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", base64.StdEncoding.EncodeToString(pub))
	return record, priv
}

func TestCacheDisabled(t *testing.T) {
	resolver := newTestCacheResolver()
	record, _ := generateTestKeyRecord(t)
	resolver.setRecord(testDomainKey, record)

	// Create validator with caching disabled
	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(0))
	require.NoError(t, err)

	// Perform multiple lookups
	for i := 0; i < 5; i++ {
		_, err := v.lookupKey(context.Background(), "example.com", "sel")
		require.NoError(t, err)
	}

	// Verify DNS lookup happened every time (no caching)
	assert.Equal(t, 5, resolver.getLookupCount(testDomainKey), "should perform DNS lookup every time when cache is disabled")

	// Verify cache is empty
	v.m.Lock()
	assert.Equal(t, 0, len(v.sigCache), "cache should be empty when disabled")
	assert.Equal(t, 0, v.cacheList.Len(), "LRU list should be empty when disabled")
	v.m.Unlock()
}

func TestBoundedCacheLRU(t *testing.T) {
	resolver := newTestCacheResolver()

	// Create validator with cache size of 3
	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(3))
	require.NoError(t, err)

	// Add 4 different keys to trigger eviction
	keys := []struct {
		domain   string
		selector string
	}{
		{"example1.com", "sel1"},
		{"example2.com", "sel2"},
		{"example3.com", "sel3"},
		{"example4.com", "sel4"},
	}

	for _, k := range keys {
		record, _ := generateTestKeyRecord(t)
		domainKey := makeDomainkey(k.selector, k.domain)
		resolver.setRecord(domainKey, record)

		_, err := v.lookupKey(context.Background(), k.domain, k.selector)
		require.NoError(t, err)
	}

	// Cache should have exactly 3 entries (LRU evicted first one)
	v.m.Lock()
	assert.Equal(t, 3, len(v.sigCache), "cache should be bounded to max size")
	assert.Equal(t, 3, v.cacheList.Len(), "LRU list should match cache size")

	// First key should have been evicted
	firstDomainKey := makeDomainkey(keys[0].selector, keys[0].domain)
	_, exists := v.sigCache[firstDomainKey]
	assert.False(t, exists, "least recently used entry should be evicted")

	// Last 3 keys should still be cached
	for i := 1; i <= 3; i++ {
		domainKey := makeDomainkey(keys[i].selector, keys[i].domain)
		_, exists := v.sigCache[domainKey]
		assert.True(t, exists, "recent entries should remain in cache")
	}
	v.m.Unlock()
}

func TestUnboundedCache(t *testing.T) {
	resolver := newTestCacheResolver()

	// Create validator with unbounded cache
	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(-1))
	require.NoError(t, err)

	// Add many keys
	numKeys := 100
	for i := 0; i < numKeys; i++ {
		record, _ := generateTestKeyRecord(t)
		domain := fmt.Sprintf("example%d.com", i)
		selector := "sel"
		domainKey := makeDomainkey(selector, domain)
		resolver.setRecord(domainKey, record)

		_, err := v.lookupKey(context.Background(), domain, selector)
		require.NoError(t, err)
	}

	// All entries should be cached (no eviction)
	v.m.Lock()
	assert.Equal(t, numKeys, len(v.sigCache), "unbounded cache should keep all entries")
	// LRU list is not used when maxCacheSize == -1
	v.m.Unlock()
}

func TestCacheHitWithLRUUpdate(t *testing.T) {
	resolver := newTestCacheResolver()

	// Create validator with cache size of 3
	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(3))
	require.NoError(t, err)

	// Add 3 keys
	keys := []struct {
		domain   string
		selector string
	}{
		{"example1.com", "sel1"},
		{"example2.com", "sel2"},
		{"example3.com", "sel3"},
	}

	for _, k := range keys {
		record, _ := generateTestKeyRecord(t)
		domainKey := makeDomainkey(k.selector, k.domain)
		resolver.setRecord(domainKey, record)

		_, err := v.lookupKey(context.Background(), k.domain, k.selector)
		require.NoError(t, err)
	}

	// Access first key again to make it most recently used
	domainKey1 := makeDomainkey(keys[0].selector, keys[0].domain)
	initialLookups := resolver.getLookupCount(domainKey1)
	_, err = v.lookupKey(context.Background(), keys[0].domain, keys[0].selector)
	require.NoError(t, err)

	// DNS lookup happens to check if record changed, but verifier is from cache
	assert.Greater(t, resolver.getLookupCount(domainKey1), initialLookups, "DNS lookup checks for record changes")

	// Add a 4th key to trigger eviction
	record4, _ := generateTestKeyRecord(t)
	domainKey4 := makeDomainkey("sel4", "example4.com")
	resolver.setRecord(domainKey4, record4)
	_, err = v.lookupKey(context.Background(), "example4.com", "sel4")
	require.NoError(t, err)

	// Second key should be evicted (it's now the LRU), not the first
	v.m.Lock()
	domainKey2 := makeDomainkey(keys[1].selector, keys[1].domain)
	_, exists := v.sigCache[domainKey2]
	assert.False(t, exists, "second entry should be evicted (LRU)")

	// First key should still be cached (was promoted to MRU)
	_, exists = v.sigCache[domainKey1]
	assert.True(t, exists, "first entry should still be cached (was promoted to MRU)")
	v.m.Unlock()
}

func TestCacheInvalidationOnRecordChange(t *testing.T) {
	resolver := newTestCacheResolver()
	record1, _ := generateTestKeyRecord(t)
	resolver.setRecord(testDomainKey, record1)

	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(10))
	require.NoError(t, err)

	// First lookup
	_, err = v.lookupKey(context.Background(), "example.com", "sel")
	require.NoError(t, err)

	// Verify it's cached
	v.m.Lock()
	cached1, exists := v.sigCache[testDomainKey]
	assert.True(t, exists, "key should be cached")
	cachedRecord1 := cached1.txt
	v.m.Unlock()

	// Second lookup should return cached entry
	initialLookups := resolver.getLookupCount(testDomainKey)
	_, err = v.lookupKey(context.Background(), "example.com", "sel")
	require.NoError(t, err)

	// DNS lookup happens (to check if record changed), but cache is used
	assert.Greater(t, resolver.getLookupCount(testDomainKey), initialLookups)
	v.m.Lock()
	cached2, exists := v.sigCache[testDomainKey]
	assert.True(t, exists)
	assert.Equal(t, cachedRecord1, cached2.txt, "cached record should not change")
	v.m.Unlock()

	// Change the DNS record
	record2, _ := generateTestKeyRecord(t)
	resolver.setRecord(testDomainKey, record2)

	// Lookup should detect record change and update cache
	_, err = v.lookupKey(context.Background(), "example.com", "sel")
	require.NoError(t, err)

	v.m.Lock()
	cached3, exists := v.sigCache[testDomainKey]
	assert.True(t, exists)
	assert.NotEqual(t, cachedRecord1, cached3.txt, "cached record should be updated")
	assert.Equal(t, record2, cached3.txt, "cache should have new record")
	v.m.Unlock()
}

func TestCacheConcurrentAccess(t *testing.T) {
	resolver := newTestCacheResolver()
	record, _ := generateTestKeyRecord(t)
	resolver.setRecord(testDomainKey, record)

	v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(10))
	require.NoError(t, err)

	// Concurrent lookups for the same key
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := v.lookupKey(context.Background(), "example.com", "sel")
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	// Should have only one entry cached
	v.m.Lock()
	assert.Equal(t, 1, len(v.sigCache), "concurrent lookups should result in single cache entry")
	v.m.Unlock()

	// DNS lookups should be minimal (some concurrent requests may all do DNS before first completes)
	lookupCount := resolver.getLookupCount(testDomainKey)
	assert.LessOrEqual(t, lookupCount, numGoroutines, "should not exceed number of concurrent requests")
}

func TestCacheSizeZeroVsNegativeOne(t *testing.T) {
	resolver := newTestCacheResolver()

	t.Run("maxCacheSize=0 disables caching", func(t *testing.T) {
		v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(0))
		require.NoError(t, err)
		assert.Equal(t, 0, v.maxCacheSize)

		record, _ := generateTestKeyRecord(t)
		domainKey := "sel._domainkey.example.com"
		resolver.setRecord(domainKey, record)

		_, err = v.lookupKey(context.Background(), "example.com", "sel")
		require.NoError(t, err)

		v.m.Lock()
		assert.Equal(t, 0, len(v.sigCache), "cache should be empty")
		v.m.Unlock()
	})

	t.Run("maxCacheSize=-1 enables unbounded caching", func(t *testing.T) {
		v, err := NewValidator(WithResolver(resolver), WithMaxCacheSize(-1))
		require.NoError(t, err)
		assert.Equal(t, -1, v.maxCacheSize)

		record, _ := generateTestKeyRecord(t)
		domainKey := "sel2._domainkey.example.com"
		resolver.setRecord(domainKey, record)

		_, err = v.lookupKey(context.Background(), "example.com", "sel2")
		require.NoError(t, err)

		v.m.Lock()
		assert.Equal(t, 1, len(v.sigCache), "unbounded cache should store entry")
		v.m.Unlock()
	})
}
