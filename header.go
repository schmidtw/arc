// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

// HeaderField identifies a message header field for inclusion in the
// ARC-Message-Signature. Standard values are provided as constants.
// Custom headers can be used by converting a string: HeaderField("X-My-Header").
type HeaderField string

// Standard header fields recommended for signing.
const (
	HeaderFrom                    HeaderField = "From"
	HeaderTo                      HeaderField = "To"
	HeaderCc                      HeaderField = "Cc"
	HeaderSubject                 HeaderField = "Subject"
	HeaderDate                    HeaderField = "Date"
	HeaderReplyTo                 HeaderField = "Reply-To"
	HeaderInReplyTo               HeaderField = "In-Reply-To"
	HeaderReferences              HeaderField = "References"
	HeaderMessageID               HeaderField = "Message-ID"
	HeaderMIMEVersion             HeaderField = "MIME-Version"
	HeaderContentType             HeaderField = "Content-Type"
	HeaderContentTransferEncoding HeaderField = "Content-Transfer-Encoding"
	HeaderResentDate              HeaderField = "Resent-Date"
	HeaderResentFrom              HeaderField = "Resent-From"
	HeaderResentTo                HeaderField = "Resent-To"
	HeaderResentCc                HeaderField = "Resent-Cc"
	HeaderListID                  HeaderField = "List-Id"
	HeaderListHelp                HeaderField = "List-Help"
	HeaderListUnsubscribe         HeaderField = "List-Unsubscribe"
	HeaderListSubscribe           HeaderField = "List-Subscribe"
	HeaderListPost                HeaderField = "List-Post"
	HeaderListOwner               HeaderField = "List-Owner"
	HeaderListArchive             HeaderField = "List-Archive"
	HeaderDKIMSignature           HeaderField = "DKIM-Signature"
)

// Headers that must not or should not be signed.
const (
	// ARC and authentication headers must not be included in signatures.
	HeaderArcSeal                  HeaderField = "ARC-Seal"
	HeaderArcMessageSignature      HeaderField = "ARC-Message-Signature"
	HeaderArcAuthenticationResults HeaderField = "ARC-Authentication-Results"
	HeaderAuthenticationResults    HeaderField = "Authentication-Results"

	// Headers commonly modified or removed in transit should not be signed.
	HeaderReturnPath HeaderField = "Return-Path"
	HeaderReceived   HeaderField = "Received"
	HeaderComments   HeaderField = "Comments"
	HeaderKeywords   HeaderField = "Keywords"
)

// excludedHeaders are headers that are silently removed from the signing list.
// ARC and Authentication-Results headers must not be signed. Headers commonly
// modified in transit (Return-Path, Received, etc.) should not be signed.
var excludedHeaders = map[HeaderField]struct{}{
	HeaderArcSeal:                  {},
	HeaderArcMessageSignature:      {},
	HeaderArcAuthenticationResults: {},
	HeaderAuthenticationResults:    {},
	HeaderReturnPath:               {},
	HeaderReceived:                 {},
	HeaderComments:                 {},
	HeaderKeywords:                 {},
}

// defaultSignedHeaders is the recommended set of headers to include in the
// ARC-Message-Signature. It includes common message headers and DKIM-Signature,
// while excluding ARC and Authentication-Results headers.
var defaultSignedHeaders = []HeaderField{
	HeaderFrom,
	HeaderTo,
	HeaderCc,
	HeaderSubject,
	HeaderDate,
	HeaderReplyTo,
	HeaderInReplyTo,
	HeaderReferences,
	HeaderMessageID,
	HeaderMIMEVersion,
	HeaderContentType,
	HeaderContentTransferEncoding,
	HeaderResentDate,
	HeaderResentFrom,
	HeaderResentTo,
	HeaderResentCc,
	HeaderListID,
	HeaderListHelp,
	HeaderListUnsubscribe,
	HeaderListSubscribe,
	HeaderListPost,
	HeaderListOwner,
	HeaderListArchive,
	HeaderDKIMSignature,
}
