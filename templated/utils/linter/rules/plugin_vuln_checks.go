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
	"strings"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

var (
	cveFormatRegexp = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// PluginVulnChecks checks that the generated vulnerability matches expectations.
type PluginVulnChecks struct{}

// Check checks the plugin against the linting rule.
func (r *PluginVulnChecks) Check(path string, plugin *tpb.TemplatedPlugin, testFile string, tests *tspb.TemplatedPluginTests) ([]*RuleResult, error) {
	if plugin == nil {
		return nil, fmt.Errorf("plugin is nil")
	}

	var results []*RuleResult

	// main_id section
	if plugin.GetFinding().GetMainId() == nil {
		results = append(results, r.missingMainID(path))
	} else {
		if plugin.GetFinding().GetMainId().GetPublisher() == "" {
			results = append(results, r.missingMainIDField(path, "publisher"))
		}

		if plugin.GetFinding().GetMainId().GetValue() == "" {
			results = append(results, r.missingMainIDField(path, "value"))
		}
	}

	// title, description, recommendation and severity
	if plugin.GetFinding().GetTitle() == "" {
		results = append(results, r.missingFindingField(path, "title"))
	}

	if plugin.GetFinding().GetDescription() == "" {
		results = append(results, r.missingFindingField(path, "description"))
	}

	if plugin.GetFinding().GetRecommendation() == "" {
		results = append(results, r.missingFindingField(path, "recommendation"))
	}

	if plugin.GetFinding().GetSeverity() == 0 {
		results = append(results, r.missingFindingField(path, "severity"))
	}

	// if the file is in the CVE directory, it should be possible to set the `related_id` field.
	if strings.Contains(path, "/cve/") {
		if len(plugin.GetFinding().GetRelatedId()) == 0 {
			results = append(results, r.missingRelatedID(path))
		} else {
			hasCVE := false
			for _, related := range plugin.GetFinding().GetRelatedId() {
				if related.GetPublisher() == "CVE" && cveFormatRegexp.MatchString(related.GetValue()) {
					hasCVE = true
				}
			}

			if !hasCVE {
				results = append(results, r.malformedRelatedID(path))
			}
		}
	}

	return results, nil
}

func (r *PluginVulnChecks) missingMainID(filename string) *RuleResult {
	reason := fmt.Sprintf("The `main_id` field is missing from the plugin finding section. Please add it.")
	return NewRuleResult("plugin-missing-main-id", reason, "", true, filename, 0)
}

func (r *PluginVulnChecks) missingMainIDField(filename, fieldname string) *RuleResult {
	reason := fmt.Sprintf("The `main_id.%s` field is missing from the plugin finding section. Please add it.", fieldname)
	return NewRuleResult("plugin-missing-main-id-publisher", reason, "", true, filename, 0)
}

func (r *PluginVulnChecks) missingFindingField(filename, fieldname string) *RuleResult {
	reason := fmt.Sprintf("The `%s` field is missing from the plugin finding section. Please add it.", fieldname)
	return NewRuleResult("plugin-missing-finding-field", reason, "", true, filename, 0)
}

func (r *PluginVulnChecks) missingRelatedID(filename string) *RuleResult {
	reason := fmt.Sprintf("The `related_id` field is missing from the plugin finding section. The plugin is in the cve directory, so it should be possible to associate it to a CVE.")
	return NewRuleResult("plugin-missing-related-id", reason, "", false, filename, 0)
}

func (r *PluginVulnChecks) malformedRelatedID(filename string) *RuleResult {
	reason := fmt.Sprintf("The `related_id` field is missing or has an invalid format. The plugin is in the cve directory, so it should be possible to associate it to a CVE.")
	return NewRuleResult("plugin-invalid-related-id", reason, "", false, filename, 0)
}
