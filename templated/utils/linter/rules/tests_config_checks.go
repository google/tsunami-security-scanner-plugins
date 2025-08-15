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

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

// TestsConfigChecks performs checks on the tests configuration.
type TestsConfigChecks struct{}

// Check checks the plugin against the linting rule.
func (r *TestsConfigChecks) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	if tests == nil {
		// Stop the rule, but do not interrupt the linting execution.
		return nil, nil
	}

	var results []*RuleResult

	// In most cases, a disabled tests highlights a mistake.
	if tests.GetConfig().GetDisabled() {
		results = append(results, r.disabledTests(testFile, plugin.GetInfo().GetName()))
	}

	// The tests are not bound to any plugin or to the wrong plugin.
	boundToPlugin := tests.GetConfig().GetTestedPlugin()
	pluginName := plugin.GetInfo().GetName()
	if boundToPlugin != pluginName {
		results = append(results, r.invalidPluginBinding(testFile, pluginName, boundToPlugin))
	}

	return results, nil
}

// Disabled tests are not allowed.
func (r *TestsConfigChecks) disabledTests(filename, pluginName string) *RuleResult {
	reason := fmt.Sprintf("Tests for plugin %q are disabled. Is this expected?", pluginName)
	return NewRuleResult("tests-disabled", reason, "", false, filename, 0)
}

// The tests are bound to the wrong plugin.
func (r *TestsConfigChecks) invalidPluginBinding(filename, pluginName, boundToPlugin string) *RuleResult {
	reason := fmt.Sprintf("Tests for plugin %q are bound to plugin %q. Is the tested_plugin field in the test config set correctly?", pluginName, boundToPlugin)
	return NewRuleResult("tests-invalid-plugin-binding", reason, "", true, filename, 0)
}
