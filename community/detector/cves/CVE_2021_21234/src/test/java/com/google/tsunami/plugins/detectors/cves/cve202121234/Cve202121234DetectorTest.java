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
package com.google.tsunami.plugins.detectors.cves.cve202121234;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;

import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link CVE202121234VulnDetector}.
 */
@RunWith(JUnit4.class)
public final class Cve202121234DetectorTest {

	private final FakeUtcClock fakeUtcClock =
			FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

	@Inject
	private CVE202121234VulnDetector detector;

	private MockWebServer mockWebServer;

	@Before
	public void setUp() {
		mockWebServer = new MockWebServer();
		Guice.createInjector(
				new FakeUtcClockModule(fakeUtcClock),
				new CVE202121234DetectorBootstrapModule(),
				new HttpClientModule.Builder().build())
				.injectMembers(this);
	}

	@After
	public void tearDown() throws IOException {
		mockWebServer.shutdown();
	}

	@Test
	public void detect_whenVulnerable_returnsVulnerability() throws IOException {
		mockWebResponse(CVE202121234VulnDetector.LINUX_DETECTION_STRING);
		NetworkService service =
				NetworkService.newBuilder()
						.setNetworkEndpoint(
								forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
						.setTransportProtocol(TransportProtocol.TCP)
						.setSoftware(Software.newBuilder().setName("http"))
						.setServiceName("http")
						.build();
		TargetInfo targetInfo =
				TargetInfo.newBuilder()
						.addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
						.build();

		DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

		assertThat(detectionReports.getDetectionReportsList())
				.containsExactly(
						DetectionReport.newBuilder()
								.setTargetInfo(targetInfo)
								.setNetworkService(service)
								.setDetectionTimestamp(
										Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
								.setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
								.setVulnerability(
										Vulnerability.newBuilder()
												.setMainId(
														VulnerabilityId.newBuilder()
																.setPublisher("TSUNAMI_COMMUNITY")
																.setValue("CVE_2021_21234"))
												.setSeverity(Severity.HIGH)
												.setTitle("CVE-2021-21234")
												.setDescription("Spring Boot Actuator Logview Arbitrary file reading").addAdditionalDetails(
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
								.build());
	}

	@Test
	public void detect_whenNotVulnerable_returnsVulnerability() throws IOException {
		mockWebResponse("Hello Word");
		ImmutableList<NetworkService> httpServices =
				ImmutableList.of(
						NetworkService.newBuilder()
								.setNetworkEndpoint(
										forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
								.setTransportProtocol(TransportProtocol.TCP)
								.setServiceName("http")
								.build());
		TargetInfo targetInfo =
				TargetInfo.newBuilder()
						.addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
						.build();

		DetectionReportList detectionReports = detector.detect(targetInfo, httpServices);

		assertThat(detectionReports.getDetectionReportsList()).isEmpty();
	}

	private void mockWebResponse(String body) throws IOException {
		mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(body));
		mockWebServer.start();
	}
}
