package com.google.tsunami.plugins.cve202138540;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Files;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.command.CommandExecutionThreadPool;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.File;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import javax.inject.Inject;

@PluginInfo(
    // Which type of plugin this is.
    type = PluginType.VULN_DETECTION,
    name = "ApacheAirflowCVE202138540VulnDetector",
    version = "0.1",
    description = "This plugin detects unauthenticated `varimport` endpoint in"
                    + "in airflow that may lead to RCE, info disclosure & DDOS.",
    author = "Sttor (security@sttor.com)",
    bootstrapModule = ApacheAirflowCVE202138540VulnDetectorBootstrapModule.class)
public final class ApacheAirflowCVE202138540VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final ListeningExecutorService commandExecutorService;
  private final File commandOutputFile;

  // Tsunami scanner relies heavily on Guice framework. So all the utility dependencies of your
  // plugin must be injected through the constructor of the detector. Here both params are provided
  // by the scanner. And the commandExecutorService is a managed ThreadPool for command execution.
  @Inject
  ApacheAirflowCVE202138540VulnDetector(
      @UtcClock Clock utcClock,
      @CommandExecutionThreadPool ListeningExecutorService commandExecutorService)
      throws IOException {
    // Create a temporary file for command output.
    this(utcClock, commandExecutorService, File.createTempFile("CVE202138540Output", ".txt"));
  }

  ApacheAirflowCVE202138540VulnDetector(
      Clock utcClock, ListeningExecutorService commandExecutorService, File commandOutputFile) {
    this.utcClock = checkNotNull(utcClock);
    this.commandExecutorService = checkNotNull(commandExecutorService);
    this.commandOutputFile = checkNotNull(commandOutputFile);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheAirflowCVE202138540VulnDetector starts detecting.");

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
    NetworkEndpoint targetEndpoint = networkService.getNetworkEndpoint();
    try {
      CommandExecutorFactory.create(
              "python3", "/usr/tsunami/python/cve202138540/apache_airflow_cve_2021_38540.py",
              "--baseUri", NetworkServiceUtils.buildWebApplicationRootUrl(networkService),
              "--output", commandOutputFile.getAbsolutePath())
          .execute(commandExecutorService)
          .waitFor();

      String outputData = Files.asCharSource(commandOutputFile, UTF_8).read();
      logger.atInfo().log(outputData);
      return outputData.startsWith("YES");
    } catch (IOException | InterruptedException | ExecutionException e) {
      logger.atWarning().withCause(e).log();
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
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_38540"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Airflow CVE-2021-38540: Unauthenticated Endpoint")
                .setCvssV3("9.8")
                .setCvssV2("7.5")
                .setDescription("The variable import endpoint was not protected by authentication "
                 + "in Airflow >=2.0.0, <2.1.3. This allowed unauthenticated users to hit that "
                 + "endpoint to add/modify Airflow variables used in DAGs, potentially resulting"
                 + "in a denial of service, information disclosure or remote code execution. "
                 + "This issue affects Apache Airflow >=2.0.0, <2.1.3." ))
        .build();
  }
}
