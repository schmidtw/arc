// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitDomainkey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		fqdn     string
		selector string
		domain   string
		errMsg   string
	}{
		{
			name:     "simple",
			fqdn:     "sel._domainkey.example.com",
			selector: "sel",
			domain:   "example.com",
		},
		{
			name:     "numeric selector",
			fqdn:     "2024._domainkey.example.com",
			selector: "2024",
			domain:   "example.com",
		},
		{
			name:     "subdomain",
			fqdn:     "sel._domainkey.mail.example.com",
			selector: "sel",
			domain:   "mail.example.com",
		},
		{
			name:   "missing marker",
			fqdn:   "sel.example.com",
			errMsg: "invalid domainkey format",
		},
		{
			name:   "empty selector",
			fqdn:   "._domainkey.example.com",
			errMsg: "selector is empty",
		},
		{
			name:   "empty domain",
			fqdn:   "sel._domainkey.",
			errMsg: "domain is empty",
		},
		{
			name:   "marker only",
			fqdn:   "._domainkey.",
			errMsg: "selector is empty",
		},
		{
			name:   "empty string",
			fqdn:   "",
			errMsg: "invalid domainkey format",
		},
		{
			name:   "no domain after marker",
			fqdn:   "sel._domainkey.",
			errMsg: "domain is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			selector, domain, err := splitDomainkey(tt.fqdn)
			if tt.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.selector, selector)
			assert.Equal(t, tt.domain, domain)
		})
	}
}
