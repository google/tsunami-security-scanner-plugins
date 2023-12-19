package com.google.tsunami.plugins.detectors.rce.torchserve;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;
import com.google.tsunami.proto.NetworkService;
import javax.inject.Inject;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "TorchServeManagementApiDetector",
    version = "0.1",
    description = "Detects publicly available TorchServe management API with a path to RCE.",
    author = "Andrew Konstantinov (andrew@doyensec.com)",
    bootstrapModule = TorchServeManagementApiDetectorBootstrapModule.class)
@ForWebService
public final class TorchServeManagementApiDetector implements VulnDetector {
  private final TorchServeExploiter torchServeExploiter;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  static final String REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  static final String REPORT_ID = "TORCHSERVE_MANAGEMENT_API_RCE";
  static final String REPORT_TITLE = "TorchServe Management API Remote Code Execution";
  static final String REPORT_RECOMMENDATION =
      "Disable the TorchServe Management API or restrict access to it.";

  @Inject
  public TorchServeManagementApiDetector(TorchServeExploiter torchServeExploiter) {
    this.torchServeExploiter = checkNotNull(torchServeExploiter);
  }

  /**
   * Detects vulnerabilities in the given target. Called by Tsunami that handles the port scanning
   * and service fingerprinting.
   *
   * @param targetInfo Information about the target system.
   * @param matchedServices List of matched network services.
   * @return A list of detection reports.
   */
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    DetectionReportList.Builder reportListBuilder = DetectionReportList.newBuilder();

    for (NetworkService service : matchedServices) {
      try {
        TorchServeExploiter.Details details = torchServeExploiter.isServiceVulnerable(service);
        logger.atInfo().log("Looking at service %s", service);
        if (details != null) {
          logger.atInfo().log("Found vulnerable service %s", service);
          DetectionReport report = buildDetectionReport(targetInfo, service, details);
          reportListBuilder.addDetectionReports(report);
        }
      } catch (Exception e) {
        logger.atWarning().withCause(e).log("Error processing service %s", service);
      }
    }
    return reportListBuilder.build();
  }

  /** Builds a vulnerability object. */
  private Vulnerability buildVulnerability(TorchServeExploiter.Details details) {
    VulnerabilityId vulnerabilityId =
        VulnerabilityId.newBuilder().setPublisher(REPORT_PUBLISHER).setValue(REPORT_ID).build();
    return Vulnerability.newBuilder()
        .setTitle(REPORT_TITLE)
        .setDescription(details.generateDescription())
        .setRecommendation(REPORT_RECOMMENDATION)
        .addAdditionalDetails(
            AdditionalDetail.newBuilder()
                .setDescription("Additional details")
                .setTextData(
                    TextData.newBuilder().setText(details.generateAdditionalDetails()).build())
                .build())
        .setSeverity(details.getSeverity())
        .setMainId(vulnerabilityId)
        .build();
  }

  /**
   * Builds a detection report for a given target and service.
   *
   * @param targetInfo Information about the target.
   * @param service The network service associated with the vulnerability.
   * @return The constructed detection report.
   */
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, TorchServeExploiter.Details details) {
    Vulnerability vulnerability = buildVulnerability(details);
    return buildDetectionReport(targetInfo, service, vulnerability, details.isVerified());
  }

  /**
   * Builds a detection report for a given target, service and vulnerability.
   *
   * @param targetInfo
   * @param service
   * @param vulnerability
   * @return The constructed detection report.
   */
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService service,
      Vulnerability vulnerability,
      boolean verified) {
    DetectionReport report =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(service)
            .setDetectionTimestamp(Timestamps.fromMillis(System.currentTimeMillis()))
            .setDetectionStatus(
                verified
                    ? DetectionStatus.VULNERABILITY_VERIFIED
                    : DetectionStatus.VULNERABILITY_PRESENT)
            .setVulnerability(vulnerability)
            .build();
    return report;
  }
}
