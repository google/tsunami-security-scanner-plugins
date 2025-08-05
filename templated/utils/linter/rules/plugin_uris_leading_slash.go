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
	"strings"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

// PluginURIHaveLeadingSlash ensure that the `uri` field in actions is `/` prefixed.
type PluginURIHaveLeadingSlash struct{}

// Check checks the plugin against the linting rule.
func (r *PluginURIHaveLeadingSlash) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	var results []*RuleResult

	for _, action := range plugin.GetActions() {
		switch action.AnyAction.(type) {
		case *tpb.PluginAction_HttpRequest:
			actionName := action.GetName()
			for _, uri := range action.GetHttpRequest().GetUri() {
				if uri == "" || !strings.HasPrefix(uri, "/") {
					finding := r.missingLeadingSlash(path, plugin.GetInfo().GetName(), actionName, uri)
					results = append(results, finding)
				}
			}
		}
	}

	return results, nil
}

// Some actions have URIs that do not have a leading slash.
func (r *PluginURIHaveLeadingSlash) missingLeadingSlash(filename, pluginName, actionName, uri string) *RuleResult {
	reason := fmt.Sprintf("Action %q defined in plugin %q: URI %q is not prefixed with a slash.", actionName, pluginName, uri)
	return NewRuleResult("plugin-uri-missing-leading-slash", reason, "", false, filename, 0)
}
