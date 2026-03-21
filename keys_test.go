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

var rsaTestKeyCache = sync.Map{}

func getRSATestKey(t *testing.T, size int) *rsa.PrivateKey {
	t.Helper()

	if key, ok := rsaTestKeyCache.Load(size); ok {
		return key.(*rsa.PrivateKey)
	}
	key, err := rsa.GenerateKey(rand.Reader, size)
	require.NoError(t, err)
	rsaTestKeyCache.Store(size, key)
	return key
}
