// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyRecord(t *testing.T) {
	pk, err := parseKeyRecord("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB")
	require.NoError(t, err)

	assert.IsType(t, &rsa.PublicKey{}, pk)
}

func TestParseKeyRecordRevokedKey(t *testing.T) {
	_, err := parseKeyRecord("v=DKIM1; k=rsa; p=")
	require.Error(t, err)
}

func TestParseKeyRecordNoP(t *testing.T) {
	_, err := parseKeyRecord("v=DKIM1; k=rsa")
	require.Error(t, err)
}

func TestParseKeyRecordUnsupportedKeyType(t *testing.T) {
	_, err := parseKeyRecord("v=DKIM1; k=dsa; p=dGVzdA==")
	require.Error(t, err)
}

func TestParseKeyRecordDefaultKeyType(t *testing.T) {
	// No k= tag should default to RSA.
	record := "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
	pk, err := parseKeyRecord(record)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, pk)
}

func TestParseKeyRecordMalformedBase64(t *testing.T) {
	_, err := parseKeyRecord("v=DKIM1; k=rsa; p=!!!notbase64!!!")
	require.Error(t, err)
}

func TestParseKeyRecordHashSHA256Accepted(t *testing.T) {
	// h=sha256 should be accepted since we support SHA-256.
	record := "v=DKIM1; k=rsa; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
	_, err := parseKeyRecord(record)
	require.NoError(t, err)
}

func TestParseKeyRecordHashExcludesSHA256(t *testing.T) {
	// h=sha1 without sha256 should be rejected.
	_, err := parseKeyRecord("v=DKIM1; k=rsa; h=sha1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB")
	require.Error(t, err)
}

func TestParseKeyRecordHashMultiple(t *testing.T) {
	// h=sha1:sha256 should be accepted since sha256 is listed.
	record := "v=DKIM1; k=rsa; h=sha1:sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
	_, err := parseKeyRecord(record)
	require.NoError(t, err)
}

func TestKeyTypeMismatch(t *testing.T) {
	// Ed25519 key type with RSA key data should fail.
	_, err := parseKeyRecord("v=DKIM1; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB")
	require.Error(t, err)
}
