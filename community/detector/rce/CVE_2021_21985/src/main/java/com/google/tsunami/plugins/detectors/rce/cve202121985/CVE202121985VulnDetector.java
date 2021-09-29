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
package com.google.tsunami.plugins.detectors.rce.cve202121985;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

@PluginInfo(
		type = PluginType.VULN_DETECTION,
		name = "CVE-2021-21985",
		version = "0.1",
		description = "Spring Boot Actuator Logview Arbitrary file reading",
		author = "hh-hunter",
		bootstrapModule = CVE202121985DetectorBootstrapModule.class)

public final class CVE202121985VulnDetector implements VulnDetector {

	private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

	private static final String CHECK_VUL_PATH = "/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData";

	private static final String CHECK_VUL_DATA = "{`\"methodInput`\":[{`\"type`\":`\"ClusterComputeResource`\",`\"value`\": null,`\"serverGuid`\": null}]}";

	public static final String DETECTION_STRING = "result";


	private final HttpClient httpClient;

	private final Clock utcClock;

	// by the scanner.
	@Inject
	CVE202121985VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
		this.httpClient = checkNotNull(httpClient);
		this.utcClock = checkNotNull(utcClock);
	}

	@Override
	public DetectionReportList detect(
			TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
		logger.atInfo().log("CVE-2021-21234 starts detecting.");

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
		String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) +
				"/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData";
		try {
			HttpHeaders headers = HttpHeaders.builder().addHeader("Content-Type", "application/json").build();
			HttpResponse httpResponse = this.httpClient.send(
					HttpRequest.post(targetUri).
							setHeaders(headers).
							setRequestBody(ByteString.copyFromUtf8(
									"{`\"methodInput`\":[{`\"type`\":`\"ClusterComputeResource`\"," +
											"`\"value`\": null,`\"serverGuid`\": null}]}")).build(),
					networkService);
			if (httpResponse.status().code() != 200) {
				return false;
			} else {
				return httpResponse.status().code() == 200 && ((String) httpResponse.bodyString().get()).contains("result");
			}
		} catch (IOException e) {
			logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
			return false;
		}
	}

	// This builds the DetectionReport message for a specific vulnerable network service.
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
												.setPublisher("hh-hunter")
												.setValue("CVE_2021_21985"))
								.setSeverity(Severity.HIGH)
								.setTitle("CVE-2021-21985")
								.setDescription("VMware vCenter Server Virtual SAN Health Check Remote Code Execution")
								.addAdditionalDetails(
										AdditionalDetail.newBuilder()
												.setTextData(
														TextData.newBuilder().setText("The vSphere Client (HTML5) " +
																"contains a remote code execution vulnerability due to " +
																"lack of input validation in the Virtual SAN Health " +
																"Check plug-in which is enabled by default in vCenter" +
																" Server. A malicious actor with network access to port " +
																"443 may exploit this issue to execute commands with " +
																"unrestricted privileges on the underlying operating" +
																" system that hosts vCenter Server."))))
				.build();
	}
}
