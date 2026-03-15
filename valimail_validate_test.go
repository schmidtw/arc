// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"context"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type valimailValidationSuite struct {
	Description string                          `yaml:"description"`
	Tests       map[string]valimailValidateTest `yaml:"tests"`
	TXTRecords  map[string]string               `yaml:"txt-records"`
}

type valimailValidateTest struct {
	Spec        string `yaml:"spec"`
	Description string `yaml:"description"`
	Message     string `yaml:"message"`
	CV          string `yaml:"cv"`
}

func TestValimailValidationSuite(t *testing.T) {
	data, err := os.ReadFile("testdata/arc-draft-validation-tests.yml")
	if err != nil {
		t.Skipf("test suite not found: %v", err)
	}

	var suite valimailValidationSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("parsing test suite: %v", err)
	}

	// Build resolver from TXT records.
	resolver := buildTXTRecordResolver(suite.TXTRecords)
	v := NewValidator(WithResolver(resolver))

	for name, tc := range suite.Tests {
		t.Run(name, func(t *testing.T) {
			msg := tc.Message

			present, err := v.Validate(context.Background(), strings.NewReader(msg))

			var got string
			switch {
			case !present && err != nil:
				t.Fatalf("Validate: %v", err)
			case !present:
				got = "None"
			case err != nil:
				got = "Fail"
			default:
				got = "Pass"
			}

			want := tc.CV

			// Empty cv in test suite means "Fail" (implementation-defined,
			// but the chain is definitely broken).
			if want == "" {
				want = "Fail"
			}

			if !strings.EqualFold(got, want) {
				t.Errorf("cv = %q, want %q (%s)", got, want, tc.Description)
			}
		})
	}
}

// buildTXTRecordResolver creates a Resolver from the test suite's txt-records map.
func buildTXTRecordResolver(records map[string]string) Resolver {
	return &mapResolver{records: records}
}
