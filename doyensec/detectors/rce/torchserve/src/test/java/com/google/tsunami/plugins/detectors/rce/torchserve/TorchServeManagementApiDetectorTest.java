package com.google.tsunami.plugins.detectors.rce.torchserve;

import static com.google.common.truth.Truth.assertThat;

import java.io.IOException;
import java.util.List;

import javax.inject.Inject;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.proto.*;

/**
 * Unit tests for {@link TorchServeManagementApiDetector}. Tested in isolation from the {@link TorchServeExploiter}.
 */
@RunWith(JUnit4.class)
public final class TorchServeManagementApiDetectorTest extends TorchServeManagementApiTestBase {
    @Inject
    private MockTorchServeExploiter exploiter;

    private TorchServeManagementApiDetector detector;

    @Override
    protected void onTestExecution() {
        detector = new TorchServeManagementApiDetector(exploiter, fakeUtcClock);
    }

    @Override
    protected Module getBaseModule() {
        Module basemoModule = super.getBaseModule();
        Module mockTorchServeExploiterModule = new AbstractModule() {
            @Override
            protected void configure() {
                bind(MockTorchServeExploiter.class);
            }
        };
        return Modules.override(basemoModule).with(mockTorchServeExploiterModule);
    }

    @Test
    public void detect_whenTorchServeIsNotVulnerable_doesNotReportVulnerability() throws IOException {
        exploiter.returnNullDetails = true;
        assertThat(getDetectionReports()).isEmpty();
    }

    @Test
    public void detect_whenTorchServiceIsVulnerableWithBasicMode_reportsVulnerability() throws IOException {
        exploiter.details.exploitationMode = TorchServeExploiter.ExploitationMode.BASIC;
        exploiter.details.models = ImmutableList.of();

        assertThat(getDetectionReports().get(0).toString())
            .isEqualTo(
                DetectionReport.newBuilder()
                    .setTargetInfo(TargetInfo.getDefaultInstance())
                    .setNetworkService(NetworkService.getDefaultInstance())
                    .setDetectionTimestamp(
                        Timestamps.fromMillis(fakeUtcClock.millis()))
                    .setDetectionStatus(DetectionStatus.VULNERABILITY_PRESENT)
                    .setVulnerability(
                        Vulnerability.newBuilder()
                            .setMainId(
                                VulnerabilityId.newBuilder()
                                    .setPublisher("DOYENSEC")
                                    .setValue("TORCHSERVE_MANAGEMENT_API_RCE"))
                            .setSeverity(Severity.HIGH)
                            .setTitle("TorchServe Management API Remote Code Execution")
                            .setDescription("An exposed TorchServe management API was detected on the target. TorchServe is a model server for PyTorch models. The management API allows adding new models to the server which by design can be used to execute arbitrary code on the target.\nThis exposure poses a significant security risk as it could allow unauthorized users to run arbitrary code on the server.")
                            .setRecommendation("It is strongly recommended to restrict access to the TorchServe Management API, as public exposure poses significant security risks. The API allows potentially disruptive interactions with TorchServe, including modifying configurations, deleting models, and altering resource allocation, which could lead to Denial of Service (DoS) attacks. \n\nParticular attention should be given to the possibility of unauthorized code execution through model uploads. Users must ensure strict control over model creation to prevent unauthorized or malicious use. Implementing the \'allowed_urls\' option in TorchServe\'s configuration is critical in this regard. This setting, detailed at https://pytorch.org/serve/configuration.html#:~:text=allowed_urls, limits the URLs from which models can be downloaded. \n\nIt is essential to configure \'allowed_urls\' as a comma-separated list of regular expressions that specifically allow only trusted sources. General whitelisting of large domains (such as entire AWS S3 or GCP buckets) is not secure. Care must be taken to ensure regex patterns are accurately defined (e.g., using \'https://models\\.my-domain\\.com/*\' instead of \'https://models.my-domain.com/*\' to prevent unintended domain matches). \n\nFinally, be aware that the Management API discloses the original URLs of downloaded models. Attackers could exploit this information to identify vulnerable download sources or to host malicious models on similarly-named domains.")
                            .addAdditionalDetails(
                                AdditionalDetail.newBuilder()
                                    .setDescription("Additional details")
                                    .setTextData(
                                        TextData.newBuilder()
                                            .setText("Callback verification is not enabled in Tsunami configuration, so the exploit could not be confirmed and only the Management API detection is reported. It is recommended to enable callback verification for more conclusive vulnerability assessment.")
                                            .build())
                                    .build())
                    .build()).toString());
    }

    @Test
    public void detect_whenTorchServiceIsVulnerableWithSsrfMode_reportsVulnerability() throws IOException {
        exploiter.details.exploitationMode = TorchServeExploiter.ExploitationMode.SSRF;
        exploiter.details.models = ImmutableList.of();
        exploiter.details.hashVerification = true;
        exploiter.details.modelName = "test_model";
        exploiter.details.exploitUrl = "http://exploit.url";

        assertThat(getDetectionReports().get(0).toString())
            .isEqualTo(
                DetectionReport.newBuilder()
                    .setTargetInfo(TargetInfo.getDefaultInstance())
                    .setNetworkService(NetworkService.getDefaultInstance())
                    .setDetectionTimestamp(
                        Timestamps.fromMillis(fakeUtcClock.millis()))
                    .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                    .setVulnerability(
                        Vulnerability.newBuilder()
                            .setMainId(
                                VulnerabilityId.newBuilder()
                                    .setPublisher("DOYENSEC")
                                    .setValue("TORCHSERVE_MANAGEMENT_API_RCE"))
                            .setSeverity(Severity.CRITICAL)
                            .setTitle("TorchServe Management API Remote Code Execution")
                            .setDescription("An exposed TorchServe management API was detected on the target. TorchServe is a model server for PyTorch models. The management API allows adding new models to the server which by design can be used to execute arbitrary code on the target.\nThis exposure poses a significant security risk as it could allow unauthorized users to run arbitrary code on the server.The exploit was confirmed by receiving a callback from the target while adding a new model with the following details:  - Name: test_model - URL: http://exploit.url")
                            .setRecommendation("It is strongly recommended to restrict access to the TorchServe Management API, as public exposure poses significant security risks. The API allows potentially disruptive interactions with TorchServe, including modifying configurations, deleting models, and altering resource allocation, which could lead to Denial of Service (DoS) attacks. \n\nParticular attention should be given to the possibility of unauthorized code execution through model uploads. Users must ensure strict control over model creation to prevent unauthorized or malicious use. Implementing the \'allowed_urls\' option in TorchServe\'s configuration is critical in this regard. This setting, detailed at https://pytorch.org/serve/configuration.html#:~:text=allowed_urls, limits the URLs from which models can be downloaded. \n\nIt is essential to configure \'allowed_urls\' as a comma-separated list of regular expressions that specifically allow only trusted sources. General whitelisting of large domains (such as entire AWS S3 or GCP buckets) is not secure. Care must be taken to ensure regex patterns are accurately defined (e.g., using \'https://models\\.my-domain\\.com/*\' instead of \'https://models.my-domain.com/*\' to prevent unintended domain matches). \n\nFinally, be aware that the Management API discloses the original URLs of downloaded models. Attackers could exploit this information to identify vulnerable download sources or to host malicious models on similarly-named domains.")
                            .addAdditionalDetails(
                                AdditionalDetail.newBuilder()
                                    .setDescription("Additional details")
                                    .setTextData(
                                        TextData.newBuilder()
                                            .setText("A callback was received from the target while adding a new model, confirming the exploit. Code execution was not verified directly. For a more direct confirmation of remote code execution, consider using STATIC or LOCAL modes.")
                                            .build())
                                    .build())
                    .build()).toString());
    }

    @Test
    public void detect_whenTorchServiceIsVulnerableWithStaticMode_reportsVulnerability() throws IOException {
        exploiter.details.exploitationMode = TorchServeExploiter.ExploitationMode.STATIC;
        exploiter.details.models = ImmutableList.of();
        exploiter.details.hashVerification = true;
        exploiter.details.modelName = "test_model";
        exploiter.details.exploitUrl = "http://exploit.url";
        exploiter.details.systemInfo = "{\"os\": \"Linux\"}";
        exploiter.details.messageLogged = "Tsunami TorchServe Plugin: Detected and executed. Refer to Tsunami Security Scanner repo for details. No malicious activity intended. Timestamp: <timestamp>";

        assertThat(getDetectionReports().get(0).toString())
            .isEqualTo(
                DetectionReport.newBuilder()
                    .setTargetInfo(TargetInfo.getDefaultInstance())
                    .setNetworkService(NetworkService.getDefaultInstance())
                    .setDetectionTimestamp(
                        Timestamps.fromMillis(fakeUtcClock.millis()))
                    .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                    .setVulnerability(
                        Vulnerability.newBuilder()
                            .setMainId(
                                VulnerabilityId.newBuilder()
                                    .setPublisher("DOYENSEC")
                                    .setValue("TORCHSERVE_MANAGEMENT_API_RCE"))
                            .setSeverity(Severity.CRITICAL)
                            .setTitle("TorchServe Management API Remote Code Execution")
                            .setDescription("An exposed TorchServe management API was detected on the target. TorchServe is a model server for PyTorch models. The management API allows adding new models to the server which by design can be used to execute arbitrary code on the target.\nThis exposure poses a significant security risk as it could allow unauthorized users to run arbitrary code on the server.The exploit was confirmed by adding a new model to the target with the following details:  - Name: test_model - URL: http://exploit.url")
                            .setRecommendation("It is strongly recommended to restrict access to the TorchServe Management API, as public exposure poses significant security risks. The API allows potentially disruptive interactions with TorchServe, including modifying configurations, deleting models, and altering resource allocation, which could lead to Denial of Service (DoS) attacks. \n\nParticular attention should be given to the possibility of unauthorized code execution through model uploads. Users must ensure strict control over model creation to prevent unauthorized or malicious use. Implementing the \'allowed_urls\' option in TorchServe\'s configuration is critical in this regard. This setting, detailed at https://pytorch.org/serve/configuration.html#:~:text=allowed_urls, limits the URLs from which models can be downloaded. \n\nIt is essential to configure \'allowed_urls\' as a comma-separated list of regular expressions that specifically allow only trusted sources. General whitelisting of large domains (such as entire AWS S3 or GCP buckets) is not secure. Care must be taken to ensure regex patterns are accurately defined (e.g., using \'https://models\\.my-domain\\.com/*\' instead of \'https://models.my-domain.com/*\' to prevent unintended domain matches). \n\nFinally, be aware that the Management API discloses the original URLs of downloaded models. Attackers could exploit this information to identify vulnerable download sources or to host malicious models on similarly-named domains.")
                            .addAdditionalDetails(
                                AdditionalDetail.newBuilder()
                                    .setDescription("Additional details")
                                    .setTextData(
                                        TextData.newBuilder()
                                            .setText("Code execution was verified by adding a new model to the target and performing following actions:\n  - Calculating a hash of a random value and comparing it to the value returned by the target (Success)\nSystem info collected from the target:\n{\n  \"os\": \"Linux\"\n}\n\nThe following log entry was generated on the target:\n\nTsunami TorchServe Plugin: Detected and executed. Refer to Tsunami Security Scanner repo for details. No malicious activity intended. Timestamp: <timestamp>")
                                            .build())
                                    .build())
                    .build()).toString());
    }

    @Test
    public void detect_whenTorchServiceIsVulnerableWithLocalMode_reportsVulnerability() throws IOException {
        exploiter.details.exploitationMode = TorchServeExploiter.ExploitationMode.LOCAL;
        exploiter.details.models = ImmutableList.of();
        exploiter.details.hashVerification = true;
        exploiter.details.modelName = "test_model";
        exploiter.details.exploitUrl = "http://exploit.url";
        exploiter.details.systemInfo = "{\"os\": \"Linux\"}";
        exploiter.details.messageLogged = "Tsunami TorchServe Plugin: Detected and executed. Refer to Tsunami Security Scanner repo for details. No malicious activity intended. Timestamp: <timestamp>";

        assertThat(getDetectionReports().get(0).toString())
            .isEqualTo(
                DetectionReport.newBuilder()
                    .setTargetInfo(TargetInfo.getDefaultInstance())
                    .setNetworkService(NetworkService.getDefaultInstance())
                    .setDetectionTimestamp(
                        Timestamps.fromMillis(fakeUtcClock.millis()))
                    .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                    .setVulnerability(
                        Vulnerability.newBuilder()
                            .setMainId(
                                VulnerabilityId.newBuilder()
                                    .setPublisher("DOYENSEC")
                                    .setValue("TORCHSERVE_MANAGEMENT_API_RCE"))
                            .setSeverity(Severity.CRITICAL)
                            .setTitle("TorchServe Management API Remote Code Execution")
                            .setDescription("An exposed TorchServe management API was detected on the target. TorchServe is a model server for PyTorch models. The management API allows adding new models to the server which by design can be used to execute arbitrary code on the target.\nThis exposure poses a significant security risk as it could allow unauthorized users to run arbitrary code on the server.The exploit was confirmed by adding a new model to the target with the following details:  - Name: test_model - URL: http://exploit.url")
                            .setRecommendation("It is strongly recommended to restrict access to the TorchServe Management API, as public exposure poses significant security risks. The API allows potentially disruptive interactions with TorchServe, including modifying configurations, deleting models, and altering resource allocation, which could lead to Denial of Service (DoS) attacks. \n\nParticular attention should be given to the possibility of unauthorized code execution through model uploads. Users must ensure strict control over model creation to prevent unauthorized or malicious use. Implementing the \'allowed_urls\' option in TorchServe\'s configuration is critical in this regard. This setting, detailed at https://pytorch.org/serve/configuration.html#:~:text=allowed_urls, limits the URLs from which models can be downloaded. \n\nIt is essential to configure \'allowed_urls\' as a comma-separated list of regular expressions that specifically allow only trusted sources. General whitelisting of large domains (such as entire AWS S3 or GCP buckets) is not secure. Care must be taken to ensure regex patterns are accurately defined (e.g., using \'https://models\\.my-domain\\.com/*\' instead of \'https://models.my-domain.com/*\' to prevent unintended domain matches). \n\nFinally, be aware that the Management API discloses the original URLs of downloaded models. Attackers could exploit this information to identify vulnerable download sources or to host malicious models on similarly-named domains.")
                            .addAdditionalDetails(
                                AdditionalDetail.newBuilder()
                                    .setDescription("Additional details")
                                    .setTextData(
                                        TextData.newBuilder()
                                            .setText("Code execution was verified by adding a new model to the target and performing following actions:\n  - Calculating a hash of a random value and comparing it to the value returned by the target (Success)\nSystem info collected from the target:\n{\n  \"os\": \"Linux\"\n}\n\nThe following log entry was generated on the target:\n\nTsunami TorchServe Plugin: Detected and executed. Refer to Tsunami Security Scanner repo for details. No malicious activity intended. Timestamp: <timestamp>")
                                            .build())
                                    .build())
                    .build()).toString());
    }

    private List<DetectionReport> getDetectionReports() {
        return detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(NetworkService.getDefaultInstance())
        ).getDetectionReportsList();
    }
}
