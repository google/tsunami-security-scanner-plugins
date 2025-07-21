// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"fmt"
	slice "slices"
	"strings"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

var (
	// These are magic markers that Tsunami will interpret differently. We need to ignore them.
	tsunamiMagicURIs = []string{
		"TSUNAMI_MAGIC_ANY_URI",
		"TSUNAMI_MAGIC_ECHO_SERVER",
	}
)

// TestsURIHaveLeadingSlash ensure that the `uri` field in mocks are `/` prefixed.
type TestsURIHaveLeadingSlash struct{}

// Check checks the plugin against the linting rule.
func (r *TestsURIHaveLeadingSlash) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	if tests == nil {
		// Stop the rule, but do not interrupt the linting execution.
		return nil, nil
	}

	pluginName := plugin.GetInfo().GetName()
	var results []*RuleResult
	for _, test := range tests.GetTests() {
		if test.GetMockHttpServer() == nil {
			continue
		}

		testName := test.GetName()
		for _, response := range test.GetMockHttpServer().GetMockResponses() {
			uri := response.GetUri()
			if slice.Contains(tsunamiMagicURIs, uri) {
				continue
			}

			if strings.HasPrefix(uri, "TSUNAMI_") && !slice.Contains(tsunamiMagicURIs, uri) {
				results = append(results, r.invalidMagic(testFile, pluginName, testName, uri))
			}

			if uri == "" || !strings.HasPrefix(uri, "/") {
				results = append(results, r.missingLeadingSlash(testFile, pluginName, testName, uri))
			}
		}
	}

	return results, nil
}

// Some tests uses HTTP mocks that have URIs without a leading slash.
func (r *TestsURIHaveLeadingSlash) missingLeadingSlash(filename, pluginName, testName, uri string) *RuleResult {
	reason := fmt.Sprintf("Test %q for plugin %q: Mocked URI %q does not have a slash prefix.", testName, pluginName, uri)
	return NewRuleResult("tests-mock-uri-missing-leading-slash", reason, "", false, filename, 0)
}

// Some tests use a mock URI that looks like a magic URI but is not.
func (r *TestsURIHaveLeadingSlash) invalidMagic(filename, pluginName, testName, uri string) *RuleResult {
	reason := fmt.Sprintf("Test %q for plugin %q: Mocked URI %q looks like a magic URI but is not. Is this expected?.", testName, pluginName, uri)
	return NewRuleResult("tests-mock-uri-invalid-magic", reason, "", false, filename, 0)
}
