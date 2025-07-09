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
	"path/filepath"
	"regexp"
	"strings"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

var (
	pluginNameConvention    = regexp.MustCompile("[a-zA-Z0-9_]+")
	pluginNameCVEConvention = regexp.MustCompile("CVE_[0-9]{4}_[0-9]{4,}$")
)

// PluginNameRespectsConvention checks that the name of the plugin follows the convention.
// See the convention: https://google.github.io/tsunami-security-scanner/howto/new-detector/templated/appendix-naming-plugin
type PluginNameRespectsConvention struct{}

// Check checks the plugin against the linting rule.
func (r *PluginNameRespectsConvention) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	var results []*RuleResult

	// the plugin name matches the regexp
	pluginName := plugin.GetInfo().GetName()
	if !pluginNameConvention.MatchString(pluginName) {
		results = append(results, r.nameFailsRegexp(pluginName, path))
	}

	// the plugin name matches the name of the file
	got := filepath.Base(path)
	want := pluginName + ".textproto"
	if got != want {
		results = append(results, r.invalidFilename(pluginName, got))
	}

	// if the plugin is in the CVE directory, its name must contain the CVE number.
	if strings.Contains(filepath.Dir(path), "/cve/") {
		if !pluginNameCVEConvention.MatchString(pluginName) {
			results = append(results, r.missingCVENumberInName(pluginName, path))
		}
	}

	return results, nil
}

// The plugin name does not match the naming regexp.
func (r *PluginNameRespectsConvention) nameFailsRegexp(pluginName, filename string) *RuleResult {
	reason := fmt.Sprintf("The plugin name %q does not match the %q convention", pluginName, pluginNameConvention.String())
	helperURL := "https://google.github.io/tsunami-security-scanner/howto/new-detector/templated/appendix-naming-plugin"
	return NewRuleResult("plugin-name-failed-regexp", reason, helperURL, true, filename, 0)
}

// The plugin name and the filename do not match.
func (r *PluginNameRespectsConvention) invalidFilename(pluginName, got string) *RuleResult {
	reason := fmt.Sprintf("The plugin name %q and filename %s do not match. Expected filename to follow the format name.textproto (%s.textproto)", pluginName, got, pluginName)
	return NewRuleResult("plugin-name-does-not-match-filename", reason, "", true, got, 0)
}

// The plugin is defined in the `cve/` directory but its name does not reflect the affected CVE.
func (r *PluginNameRespectsConvention) missingCVENumberInName(pluginName, filename string) *RuleResult {
	reason := fmt.Sprintf("The plugin %q is in the CVE directory its name does not match the `CVE_YYYY_NNNN` convention", pluginName)
	helperURL := "https://google.github.io/tsunami-security-scanner/howto/new-detector/templated/appendix-naming-plugin"
	return NewRuleResult("plugin-name-missing-cve-number", reason, helperURL, true, filename, 0)
}
