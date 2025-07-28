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
	"github.com/rs/zerolog/log"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

// Rule provides the interface to define a linting rule.
type Rule interface {
	// Checks a given plugin and/or its tests against the linting rule and return a list of results.
	Check(string, *tpb.TemplatedPlugin, string, *tspb.TemplatedPluginTests) ([]*RuleResult, error)
}

// RuleResult provides the interface to define the result of a linting rule.
type RuleResult struct {
	// Identifier of the linter rule.
	identifier string

	// Whether this is a blocking result.
	blocking bool

	// Reason why the linter notified an issue.
	reason string

	// HelperURL to a page that can be used to resolve the issue highlighted by the rule.
	helperURL string

	// Filename that caused the issue to be raised.
	filename string

	// LineNumber were the issue was found.
	lineNumber int
}

// Log the result.
func (r *RuleResult) Log() {
	helperURL := "None"
	if r.helperURL != "" {
		helperURL = r.helperURL
	}

	logger := log.With().
		Str("linter", r.identifier).
		Str("documentation", helperURL).
		Str("filename", r.filename).
		Logger()

	if r.blocking {
		logger.Error().Msg(r.reason)
	} else {
		logger.Warn().Msg(r.reason)
	}
}

// Blocking returns whether the result should be a blocker for merging the plugin.
func (r *RuleResult) Blocking() bool {
	return r.blocking
}

// NewRuleResult creates a new RuleResult.
func NewRuleResult(identifier, reason, helperURL string, blocking bool, filename string, lineNumber int) *RuleResult {
	return &RuleResult{
		identifier: identifier,
		blocking:   blocking,
		reason:     reason,
		helperURL:  helperURL,
		filename:   filename,
		lineNumber: lineNumber,
	}
}
