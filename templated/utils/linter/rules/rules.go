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

// Package rules provides linting rules and the list of enabled rules.
package rules

import (
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

// EnabledRules is the list of enabled linting rules.
var EnabledRules = []Rule{
	&PluginVulnChecks{},
	&PluginConfigChecks{},
	&TestsConfigChecks{},
	&PluginActionChecks{},
	&TestsURIHaveLeadingSlash{},
	&PluginURIHaveLeadingSlash{},
	&PluginNameRespectsConvention{},
}

// RunAll runs all the enabled linting rules against the given plugin and its tests.
func RunAll(pluginPath string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	var results []*RuleResult

	for _, rule := range EnabledRules {
		r, err := rule.Check(pluginPath, plugin, testFile, tests)
		if err != nil {
			return nil, err
		}

		results = append(results, r...)
	}

	return results, nil
}
