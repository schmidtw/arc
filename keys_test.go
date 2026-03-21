// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var rsaTestKeyCache = map[int]*rsa.PrivateKey{}
var rsaTestKeyCacheMu sync.Mutex

// getRSATestKey returns a cached RSA test key of the given size.
// Keys are generated lazily and cached for reuse across tests.
//
// Note: If multiple goroutines request the same uncached size concurrently,
// they may both generate keys, but LoadOrStore ensures only one is stored.
// This is acceptable for test code - duplicate generation is rare and harmless.
func getRSATestKey(t *testing.T, size int) *rsa.PrivateKey {
	t.Helper()
	rsaTestKeyCacheMu.Lock()
	defer rsaTestKeyCacheMu.Unlock()

	if key, ok := rsaTestKeyCache[size]; ok {
		return key
	}

	// Generate key (may happen concurrently for same size).
	key, err := rsa.GenerateKey(rand.Reader, size)
	require.NoError(t, err)

	rsaTestKeyCache[size] = key
	return key
}
