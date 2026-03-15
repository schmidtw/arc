// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

// Key type identifiers used in DNS key records.
const (
	algoRSA     = "rsa"
	algoEd25519 = "ed25519"
)

// Hash algorithm identifier.
const hashSHA256 = "sha256"

// Signing algorithm identifiers (as they appear in ARC headers).
const (
	algRSASHA256     = "rsa-sha256"
	algEd25519SHA256 = "ed25519-sha256"
)
