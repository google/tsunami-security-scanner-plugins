/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableSet.toImmutableSet;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.composer.WeakCredentialComposer;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.CredentialType;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ncrack.NcrackCredentialTester;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.Credential;
import com.google.tsunami.proto.Credentials;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;

/**
 * The weak credentials plugins checks credentials on all the services supported by testers like
 * {@link NcrackCredentialTester}. See the {@link CredentialProvider}s registered in {@link
 * GenericWeakCredentialDetectorBootstrapModule} for the list of passwords checked by the detector.
 * Add additional {@link CredentialProvider} to test more credentials.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GenericCredentialDetectorPlugin",
    version = "0.1",
    description = "Checks for weak credentials using tools like ncrack (https://nmap.org/ncrack/).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = GenericWeakCredentialDetectorBootstrapModule.class)
public final class GenericWeakCredentialDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Severity DEFAULT_SEVERITY = Severity.CRITICAL;

  @VisibleForTesting
  final ImmutableSet<CredentialProvider> providers;
  private final ImmutableSet<CredentialTester> testers;
  private final Clock utcClock;

  // TODO(b/287138065): Abstract out service type, which could have multiple names like "mongod" &
  // "mongodb"
  // By default, a cred tester uses all the credentials provided by all the providers.
  // If a tester prefer faster scanning, explicitly specify the types of credentials to be used.
  private static final ImmutableMultimap<String, CredentialType>
      SERVICE_SPECIFIC_CREDENTIALS_OVERRIDE = ImmutableMultimap.of();

  private static final ImmutableMap<String, String> FINDING_SERVICE_OVERRIDE =
      ImmutableMap.of("ms-wbt-server", "rdp");

  @Inject
  GenericWeakCredentialDetector(
      Set<CredentialProvider> providers,
      Set<CredentialTester> testers,
      @UtcClock Clock utcClock,
      HttpClient httpClient) {
    this(
        ImmutableSet.copyOf(checkNotNull(providers)),
        ImmutableSet.copyOf(checkNotNull(testers)),
        utcClock,
        httpClient);
  }

  @VisibleForTesting
  GenericWeakCredentialDetector(
      ImmutableSet<CredentialProvider> providers,
      ImmutableSet<CredentialTester> testers,
      Clock utcClock,
      HttpClient httpClient) {
    this.providers = checkNotNull(providers);
    this.testers = checkNotNull(testers);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting weak credential detection.");
    Stopwatch stopwatch = Stopwatch.createStarted();
    DetectionReportList.Builder detectionReportsBuilder = DetectionReportList.newBuilder();

    matchedServices.stream()
        .filter(
            networkService -> testers.stream().anyMatch(tester -> tester.canAccept(networkService)))
        .forEach(
            networkService ->
                testServiceAndAddDetectionReport(
                    targetInfo, networkService, detectionReportsBuilder));
    logger.atInfo().log("Weak credential detection finished in %s.", stopwatch.stop());
    return detectionReportsBuilder.build();
  }

  private void testServiceAndAddDetectionReport(
      TargetInfo targetInfo,
      NetworkService networkService,
      DetectionReportList.Builder detectionReportsBuilder) {
    ImmutableList<TestCredential> weakCredentials =
        testers.stream()
            .filter(tester -> tester.canAccept(networkService))
            .map(tester -> runTesterAndAddFinding(networkService, tester))
            .flatMap(Collection::stream)
            .collect(toImmutableList());

    if (!weakCredentials.isEmpty()) {
      addFindingForCredential(targetInfo, networkService, weakCredentials, detectionReportsBuilder);
    }
  }

  private ImmutableList<TestCredential> runTesterAndAddFinding(
      NetworkService networkService, CredentialTester tester) {

    // Multiple providers could give the same credentials, so create
    // a set to dedupe them before testing.
    HashSet<TestCredential> credentials = new LinkedHashSet<>();

    String serviceName = NetworkServiceUtils.getServiceName(networkService);

    ImmutableSet<CredentialProvider> effectiveProvider = providers;
    if (SERVICE_SPECIFIC_CREDENTIALS_OVERRIDE.containsKey(serviceName)) {
      ImmutableCollection<CredentialType> credTypes =
          SERVICE_SPECIFIC_CREDENTIALS_OVERRIDE.get(serviceName);
      effectiveProvider =
          providers.stream()
              .filter(provider -> credTypes.contains(provider.type()))
              .collect(toImmutableSet());
    }

    // Sort all providers according to their priorities
    ImmutableList<CredentialProvider> prioritizedCredProviders =
        ImmutableList.sortedCopyOf(CredentialProvider.comparator(), effectiveProvider);
    for (CredentialProvider provider : prioritizedCredProviders) {
      provider.generateTestCredentials(networkService).forEachRemaining(credentials::add);
    }

    return new WeakCredentialComposer(ImmutableList.copyOf(credentials), tester)
        .run(networkService);
  }

  private void addFindingForCredential(
      TargetInfo targetInfo,
      NetworkService networkService,
      ImmutableList<TestCredential> testCredentials,
      DetectionReportList.Builder detectionReportsBuilder) {
    detectionReportsBuilder.addDetectionReports(
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(networkService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("GOOGLE")
                            .setValue(buildVulnerabilityId(networkService)))
                    .setSeverity(DEFAULT_SEVERITY)
                    .setTitle(buildTitle(networkService))
                    .setCvssV3("7.5") // CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
                    .setDescription(buildDescription(networkService))
                    .setRecommendation("Change the password of all affected users to a strong one.")
                    .addAdditionalDetails(buildCredentialDetail(testCredentials)))
            .build());
  }

  private static String buildVulnerabilityId(NetworkService networkService) {
    return "WEAK_CREDENTIALS_FOR_" + Ascii.toUpperCase(getServiceName(networkService));
  }

  private static String getServiceName(NetworkService networkService) {
    String serviceName = NetworkServiceUtils.getServiceName(networkService);
    if (FINDING_SERVICE_OVERRIDE.containsKey(serviceName)) {
      return FINDING_SERVICE_OVERRIDE.get(serviceName);
    }

    String webServiceName = NetworkServiceUtils.getWebServiceName(networkService);
    return webServiceName.isEmpty() ? serviceName : webServiceName;
  }

  private static String buildTitle(NetworkService networkService) {
    return String.format("Weak '%s' service credential", getServiceName(networkService));
  }

  private static String buildDescription(NetworkService networkService) {
    String affectedService = getServiceName(networkService);
    String affectedPort =
        networkService.getNetworkEndpoint().hasPort()
            ? String.valueOf(networkService.getNetworkEndpoint().getPort().getPortNumber())
            : "unknown";
    return String.format(
        "Well known or weak credentials are detected for '%s' service on port '%s'.",
        affectedService, affectedPort);
  }

  private static AdditionalDetail buildCredentialDetail(
      ImmutableList<TestCredential> testCredentials) {
    List<Credential> credentials = new ArrayList<>();
    for (TestCredential cred : testCredentials) {
      Credential.Builder credentialBuilder = Credential.newBuilder().setUsername(cred.username());
      cred.password().ifPresent(credentialBuilder::setPassword);
      credentials.add(credentialBuilder.build());
    }
    return AdditionalDetail.newBuilder()
        .setDescription("Identified credential(s)")
        .setCredentials(Credentials.newBuilder().addAllCredential(credentials))
        .build();
  }

}
