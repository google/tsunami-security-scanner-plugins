/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.kubereadonly;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin to find Kube clusters with read-only-port enabled. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "KubeReadOnlyPortDetector",
    version = "0.1",
    description =
        "Tsunami plugin to detect Kubernetes clusters leaking info via the read-only-port feature"
            + " of the kubelet process.",
    author = "Imre Rad (imrer@google.com)",
    bootstrapModule = KubeReadOnlyPortDetectorBootstrapModule.class)
public final class KubeReadOnlyPortDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  private static final String FINDING_DESCRIPTION_TEXT =
      "Kubernetes/kubelet exposes a read-only TCP port 10255 which shows the"
          + " configurations of all pods on the cluster at the /pods API endpoint,"
          + " which might contain sensitive information.\n"
          + "Some managed Kubernetes clusters enable this feature by default.\n"
          + "An example is GKE, where this port is open inside the private VPC"
          + " network by default (but is blocked from the internet).\n"
          + "\n"
          + "The read-only-port feature poses the risk of information leak.\n"
          + "\n"
          + "You can find more information and additional technical details in the"
          + " following article:\n"
          + "https://www.deepnetwork.com/blog/2020/01/13/kubelet-api.html#read-only-port-endpoints";

  private static final String FINDING_RECOMMENDATION_TEXT =
      "At first, please verify if this port (tcp/10255 by default) is accessible via the public IP"
          + " address of your Kubernetes nodes. Example command:\n"
          + "\n"
          + "curl -v http://$PUBLIC_NODE_IP:10255/pods\n"
          + "\n"
          + "As a next step, you may either:\n"
          + "- explicitly disable this feature by setting `read-only-port` to 0\n"
          + "- ensure that only trusted parties have network access to this port\n"
          + "\n\n"
          + "Google Cloud Platform related instructions:\n\n"
          + "To identify firewall rules that may be responsible for the exposure, run the following"
          + " command:\n"
          + "\n"
          + "gcloud compute firewall-rules list --filter=\"disabled=False AND direction=INGRESS AND"
          + " sourceRanges=(0.0.0.0/0) AND ((allowed.IPProtocol=all OR allowed.IPProtocol=tcp) AND"
          + " (allowed.ports=null OR allowed.ports=(1-65535) OR allowed.ports=10255))\""
          + " --format=yaml --project=$PROJECTID\n"
          + "\n"
          + "This list is a superset of firewall rules that may be responsible for the exposure.Be"
          + " sure to inspect targetTags and targetServiceAccounts to understand the scope of the"
          + " rules.\n"
          + "\n"
          + "For example, assume a firewall rule with the name allow-all appears in the prior"
          + " command's output. To mitigate the vulnerability, delete the allow-all firewall rule"
          + " by running the following command:\n"
          + "\n"
          + "Example: gcloud compute firewall-rules delete allow-all\n"
          + "\n"
          + "While security best practice recommends deleting overly permissive firewall rules,"
          + " deleting these rules may risk service disruptions. If deleting firewall rules found"
          + " in the previous step is not feasible, an alternative approach is to create a high"
          + " priority firewall rule that explicitly allows internal access to TCP port 10255 then"
          + " create a deny rule for all other ingress to port 10255. Ensure that network,"
          + " source-ranges, target-tags or target-service-accounts are set appropriately for your"
          + " environment when running the following commands.\n"
          + "\n"
          + "Example: Only allow RFC1918 traffic to access TCP 10255 with 0 (highest) priority:\n"
          + "\n"
          + "gcloud compute --project=$PROJECTID firewall-rules create allow-internal-kubelet-ro"
          + " --direction=INGRESS --priority=0 --network=default --action=ALLOW --rules=tcp:10255"
          + " --source-ranges=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16\n"
          + "\n"
          + "Deny all traffic access to TCP 10255 with 1 (lower) priority:\n"
          + "\n"
          + "Example: gcloud compute --project=$PROJECTID firewall-rules create"
          + " deny-kubelet-ro--direction=INGRESS --priority=1 --network=default --action=DENY"
          + " --rules=tcp:10255\n"
          + "--source-ranges=0.0.0.0/0\n"
          + "\n"
          + "Once this is complete, verify the exposure of your service by re-running the curl"
          + " command above.\n";

  @Inject
  KubeReadOnlyPortDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("KubeReadOnlyPortDetector starts detecting.");

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
    String uriAuthority = toUriAuthority(networkService.getNetworkEndpoint());
    String targetUri = String.format("http://%s%s", uriAuthority, "/pods");
    HttpRequest req = HttpRequest.get(targetUri).withEmptyHeaders().build();

    try {
      HttpResponse res = this.httpClient.send(req, networkService);

      // If the service is vulnerable, we receive a healthy json response.
      if (!res.status().isSuccess()) {
        return false;
      }

      // {"kind":"PodList",...
      JsonObject jsonResponse =
          (JsonObject) res.bodyJson().get(); // will throw if it is not json or not an object
      JsonPrimitive kindPrimitive = jsonResponse.getAsJsonPrimitive("kind");
      String kind = kindPrimitive.getAsString();

      return "PodList".equals(kind);

    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "Fail to exploit '%s'. Maybe it is not vulnerable", targetUri);
      return false;
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
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("KUBERNETES_READ_ONLY_PORT"))
                .setSeverity(Severity.MEDIUM)
                .setTitle("Information leak via the read-only-port feature of Kubernetes/kubelet")
                .setDescription(FINDING_DESCRIPTION_TEXT)
                .setRecommendation(FINDING_RECOMMENDATION_TEXT))
        .build();
  }
}
