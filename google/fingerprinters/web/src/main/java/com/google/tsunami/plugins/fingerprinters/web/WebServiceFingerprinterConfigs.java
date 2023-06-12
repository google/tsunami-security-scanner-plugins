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
import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.common.config.annotations.ConfigProperties;
import java.util.List;
import javax.inject.Inject;

/** Configuration options for {@link WebServiceFingerprinter}. */
public final class WebServiceFingerprinterConfigs {
  private static final int DEFAULT_MAX_FAILED_SIFTING_REQUEST = 20;
  private static final int DEFAULT_MAX_ALLOWED_SIFTING_REQUEST = 100;
  private static final long DEFAULT_MAX_RECORDING_CONTENT_SIZE = 10240; // 0.1 MB
  private static final ImmutableList<String> DEFAULT_FILE_EXTENSION_EXCLUSIONS =
      ImmutableList.of("application/zip", "application/gzip");

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

  public int getMaxAllowedSiftingRequest() {
    if (cliOptions.maxAllowedSiftingRequest != null) {
      return cliOptions.maxAllowedSiftingRequest;
    } else if (configProperties.maxAllowedSiftingRequest != null) {
      return configProperties.maxAllowedSiftingRequest;
    } else {
      return DEFAULT_MAX_ALLOWED_SIFTING_REQUEST;
    }
  }

  public int getMaxFailedSiftingRequests() {
    if (cliOptions.maxFailedSiftingRequest != null) {
      return cliOptions.maxFailedSiftingRequest;
    } else if (configProperties.maxFailedSiftingRequest != null) {
      return configProperties.maxFailedSiftingRequest;
    } else {
      return DEFAULT_MAX_FAILED_SIFTING_REQUEST;
    }
  }

  public long getMaxRecordingContentSize() {
    if (cliOptions.maxRecordingContentSize != null) {
      return cliOptions.maxRecordingContentSize;
    } else if (configProperties.maxRecordingContentSize != null) {
      return configProperties.maxRecordingContentSize;
    } else {
      return DEFAULT_MAX_RECORDING_CONTENT_SIZE;
    }
  }

  public List<String> getContentTypeExclusions() {
    if (cliOptions.contentTypeExclusions != null) {
      return cliOptions.contentTypeExclusions;
    } else if (configProperties.contentTypeExclusions != null) {
      return configProperties.contentTypeExclusions;
    } else {
      return DEFAULT_FILE_EXTENSION_EXCLUSIONS;
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

    @Parameter(
        names = "--web-service-fingerprinter-max-allowed-sifting-request",
        description =
            "The maximum number of allowed HTTP requests for the version sifting logic. The"
                + " WebServiceFingerprinter's version detection logic narrows down the version"
                + " scope of the scan target by sending additional probes to un-crawled web"
                + " resources on the target. This flag controls the maximum number of probes it"
                + " can send to the target.")
    Integer maxAllowedSiftingRequest;

    @Parameter(
        names = "--web-service-fingerprinter-max-failed-sifting-request",
        description =
            "The maximum number of allowed HTTP requests that can fail for the version sifting"
                + " logic. The WebServiceFingerprinter's version detection logic narrows down the"
                + " version scope of the scan target by sending additional probes to un-crawled"
                + " web resources on the target. This flag controls the maximum number of failed"
                + " probes.")
    Integer maxFailedSiftingRequest;

    @Parameter(
        names = "--web-service-fingerprinter-crawl-result-recording-max-content-size",
        description =
            "The maximum content size in bytes the web fingerprinter stores as part of the"
                + " crawl results in the final scan results. Large content size could increase"
                + " memory usage when crawling web services hosting large static files and trigger"
                + " OOM errors. The content larger than the limit are still hashed for service"
                + " fingerprint, they are only excluded in the WebServiceContext for recording"
                + " purpose. Default to 10KB. ")
    Long maxRecordingContentSize;

    @Parameter(
        names = "--web-service-fingerprinter-crawl-result-recording-content-type-exclusions",
        description =
            "A comma separated list of content type to exclude when recording the crawled content"
                + "in WebServiceContext. The excluded content are still used for hashing web "
                + "fingerprints. They are only excluded in the WebServiceContext for recording "
                + "purpose.")
    List<String> contentTypeExclusions;

    @Override
    public void validate() {}
  }

  @ConfigProperties("plugins.google.fingerprinter.web")
  static final class WebServiceFingerprinterConfigProperties {

    /**
     * Configuration options for the {@code
     * --web-service-fingerprinter-enforce-crawling-scope-check} CLI flag. See the CLI flag's
     * description for more details.
     */
    Boolean enforceCrawlingScopeCheck;

    /**
     * Configuration options for the {@code --web-service-fingerprinter-max-allowed-sifting-request}
     * CLI flag. See the CLI flag's description for more details.
     */
    Integer maxAllowedSiftingRequest;

    /**
     * Configuration options for the {@code --web-service-fingerprinter-max-failed-sifting-request}
     * CLI flag. See the CLI flag's description for more details.
     */
    Integer maxFailedSiftingRequest;

    /**
     * Configuration option for the @code --web-service-fingerprinter-max-recording-file-size} CLI
     * flag. See the CLI flag's description for more details.
     */
    Long maxRecordingContentSize;

    /**
     * Configuration option for the @code
     * --web-service-fingerprinter-crawl-result-recording-content-type-exclusions} CLI flag. See the
     * CLI flag's description for more details.
     */
    List<String> contentTypeExclusions;
  }
}
