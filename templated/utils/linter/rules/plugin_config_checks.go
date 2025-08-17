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

// PluginConfigChecks checks the config section of the plugin.
type PluginConfigChecks struct{}

// Check checks the plugin against the linting rule.
func (r *PluginConfigChecks) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	var results []*RuleResult
	pluginName := plugin.GetInfo().GetName()

	// Check that debug is not be enabled.
	if plugin.GetConfig().GetDebug() {
		results = append(results, r.debugModeEnabled(path, pluginName))
	}

	// Check that the plugin is not disabled.
	if plugin.GetConfig().GetDisabled() {
		results = append(results, r.pluginDisabled(path, pluginName))
	}

	return results, nil
}

func (r *PluginConfigChecks) debugModeEnabled(filename, pluginName string) *RuleResult {
	reason := fmt.Sprintf("Plugin %q is in debug mode. Please disable debug mode before merging the plugin.", pluginName)
	return NewRuleResult("plugin-debug-mode", reason, "", true, filename, 0)
}

func (r *PluginConfigChecks) pluginDisabled(filename, pluginName string) *RuleResult {
	reason := fmt.Sprintf("Plugin %q is disabled. Please enable the plugin before merging it.", pluginName)
	return NewRuleResult("plugin-disabled", reason, "", true, filename, 0)
}
