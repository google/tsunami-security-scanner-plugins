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

// Package main defines the linter entrypoint.
package main

import (
	"os"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/prototext"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	tspb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	"github.com/google/tsunami-security-scanner-plugins/templated/utils/linter/rules"
)

var (
	simplifyPathRegexp = regexp.MustCompile(`templated/templateddetector/plugins/.+`)
)

func loadPlugin(path string) (*tpb.TemplatedPlugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var plugin tpb.TemplatedPlugin
	if err := prototext.Unmarshal(data, &plugin); err != nil {
		return nil, err
	}

	return &plugin, nil
}

func loadTests(path string) (*tspb.TemplatedPluginTests, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pluginTests tspb.TemplatedPluginTests
	if err := prototext.Unmarshal(data, &pluginTests); err != nil {
		return nil, err
	}

	return &pluginTests, nil
}

func main() {
	// configure logging
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:     os.Stderr,
		NoColor: false,
	})

	if len(os.Args) != 2 {
		log.Panic().Msg("Usage: linter <plugin_file>")
	}

	pluginPath := os.Args[1]
	simplePluginPath := simplifyPathRegexp.FindString(pluginPath)
	plugin, err := loadPlugin(pluginPath)
	if err != nil {
		log.Panic().Err(err)
	}

	testFile := strings.Replace(pluginPath, ".textproto", "_test.textproto", 1)
	simpleTestFilepath := simplifyPathRegexp.FindString(testFile)
	var results []*rules.RuleResult
	tests, err := loadTests(testFile)
	if err != nil {
		results = append(results, noTestFinding(pluginPath))
	}

	r, err := rules.RunAll(simplePluginPath, plugin, simpleTestFilepath, tests)
	if err != nil {
		log.Panic().Err(err)
	}

	results = append(results, r...)
	exitcode := 0
	for _, result := range results {
		if result.Blocking() {
			exitcode = 1
		}

		result.Log()
	}

	os.Exit(exitcode)
}

func noTestFinding(testFilepath string) *rules.RuleResult {
	reason := "No tests found for plugin with auto-detected path. Did you write tests? Did you use the `_test.textproto` pattern for the filename?"
	return rules.NewRuleResult("test-file-not-found", reason, "", false, testFilepath, 0)
}
