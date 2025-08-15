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
	"regexp"
	"slices"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

var (
	actionNameConvention = regexp.MustCompile("^[a-zA-Z0-9_]+$")
)

// PluginActionChecks checks the actions defined in the plugin.
type PluginActionChecks struct{}

// Check checks the plugin against the linting rule.
func (r *PluginActionChecks) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	var results []*RuleResult
	var actionNames []string
	var usedActionNames []string

	// Cache action names and references to these names.
	for _, action := range plugin.GetActions() {
		actionNames = append(actionNames, action.GetName())
		cleanups := action.GetCleanupActions()
		usedActionNames = append(usedActionNames, cleanups...)
	}

	for _, workflow := range plugin.GetWorkflows() {
		for _, action := range workflow.GetActions() {
			usedActionNames = append(usedActionNames, action)
		}
	}

	// Check the names of the actions.
	pluginName := plugin.GetInfo().GetName()
	for _, action := range actionNames {
		if !actionNameConvention.MatchString(action) {
			results = append(results, r.invalidActionName(path, pluginName, action))
		}
	}

	// Check that all cleanups actions are defined.
	for _, action := range plugin.GetActions() {
		actionName := action.GetName()
		for _, cleanup := range action.GetCleanupActions() {
			if !slices.Contains(actionNames, cleanup) {
				results = append(results, r.undefinedCleanup(path, pluginName, actionName, cleanup))
			}
		}
	}

	// Check that all actions defined in workflows are defined.
	for i, workflow := range plugin.GetWorkflows() {
		for _, action := range workflow.GetActions() {
			if !slices.Contains(actionNames, action) {
				results = append(results, r.undefinedAction(path, pluginName, i, action))
			}
		}
	}

	// Check that all actions are used.
	for _, action := range actionNames {
		if !slices.Contains(usedActionNames, action) {
			results = append(results, r.unusedAction(path, pluginName, action))
		}
	}

	return results, nil
}

// An action has a name that does not match the convention.
func (r *PluginActionChecks) invalidActionName(filename, pluginName, actionName string) *RuleResult {
	reason := fmt.Sprintf("Action %q defined in plugin %q: Name does not match the `[a-zA-Z0-9_]` convention.", actionName, pluginName)
	helperURL := "https://google.github.io/tsunami-security-scanner/howto/new-detector/templated/appendix-naming-actions"
	return NewRuleResult("plugin-action-invalid-name", reason, helperURL, true, filename, 0)
}

// A cleanup action is not defined in the plugin.
func (r *PluginActionChecks) undefinedCleanup(filename, pluginName, actionName, cleanupName string) *RuleResult {
	reason := fmt.Sprintf("Action %q in plugin %q references %q as a cleanup but it is never defined.", actionName, pluginName, cleanupName)
	return NewRuleResult("plugin-cleanup-not-defined", reason, "", true, filename, 0)
}

// An action defined in a workflow is not defined in the plugin.
func (r *PluginActionChecks) undefinedAction(filename, pluginName string, workflowIndex int, actionName string) *RuleResult {
	reason := fmt.Sprintf("Workflow %d in plugin %q references %q as an action but it is never defined.", workflowIndex, pluginName, actionName)
	return NewRuleResult("plugin-action-not-defined", reason, "", true, filename, 0)
}

// An action is defined but is never used.
func (r *PluginActionChecks) unusedAction(filename, pluginName, actionName string) *RuleResult {
	reason := fmt.Sprintf("Action %q in plugin %q is never used.", actionName, pluginName)
	return NewRuleResult("plugin-action-unused", reason, "", true, filename, 0)
}
