// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"fmt"
	"strings"
)

func splitDomainkey(fqdn string) (selector, domain string, err error) {
	selector, domain, ok := strings.Cut(fqdn, "._domainkey.")
	if !ok {
		return "", "", fmt.Errorf("invalid domainkey format: %s should be '<selector>._domainkey.example.com'", fqdn)
	}

	if selector == "" {
		return "", "", fmt.Errorf("invalid domainkey format: selector is empty in %s", fqdn)
	}
	if domain == "" {
		return "", "", fmt.Errorf("invalid domainkey format: domain is empty in %s", fqdn)
	}
	return selector, domain, nil
}

func makeDomainkey(selector, domain string) string {
	return selector + "._domainkey." + domain
}
