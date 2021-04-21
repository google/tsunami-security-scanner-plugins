/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.fingerprinters.web;

import static com.google.common.base.Preconditions.checkNotNull;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.common.config.annotations.ConfigProperties;
import javax.inject.Inject;

/** Configuration options for {@link WebServiceFingerprinter}. */
public final class WebServiceFingerprinterConfigs {

  private final WebServiceFingerprinterCliOptions cliOptions;
  private final WebServiceFingerprinterConfigProperties configProperties;

  @Inject
  WebServiceFingerprinterConfigs(
      WebServiceFingerprinterCliOptions cliOptions,
      WebServiceFingerprinterConfigProperties configProperties) {
    this.cliOptions = checkNotNull(cliOptions);
    this.configProperties = checkNotNull(configProperties);
  }

  public boolean shouldEnforceCrawlingScopeCheck() {
    if (cliOptions.enforceCrawlingScopeCheck != null) {
      return cliOptions.enforceCrawlingScopeCheck;
    } else if (configProperties.enforceCrawlingScopeCheck != null) {
      return configProperties.enforceCrawlingScopeCheck;
    } else {
      // By default the crawler should enforce scope check for the crawled web domains.
      return true;
    }
  }

  @Parameters(separators = "=")
  static final class WebServiceFingerprinterCliOptions implements CliOption {

    @Parameter(
        names = "--web-service-fingerprinter-enforce-crawling-scope-check",
        description =
            "Whether the WebServiceFingerprinter plugin should enforce the crawling scope check."
                + " When true, only resources served on the scan target domain are considered in"
                + " scope for fingerprinting. Otherwise all crawled resources are used for"
                + " fingerprinting.",
        arity = 1)
    Boolean enforceCrawlingScopeCheck;

    @Override
    public void validate() {}
  }

  @ConfigProperties("plugins.google.fingerprinter.web")
  static final class WebServiceFingerprinterConfigProperties {

    /**
     * Configuration options for the {@code --web-service-fingerprinter-enforce-crawling-spoc-check}
     * CLI flag. See the CLI flag's description for more details.
     */
    Boolean enforceCrawlingScopeCheck;
  }
}
