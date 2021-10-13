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
package com.google.tsunami.plugins.detectors.cves.cve202122986;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Instant;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;


/**
 * Unit tests for {@link CVE202122986VulnDetector}.
 */
@RunWith(JUnit4.class)
public final class CVE202122986DetectorTest {

	private final FakeUtcClock fakeUtcClock =
			FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

	@Inject
	private CVE202122986VulnDetector detector;

	private MockWebServer mockWebServer;

	@Before
	public void setUp() {
		mockWebServer = new MockWebServer();
		Guice.createInjector(
				new FakeUtcClockModule(fakeUtcClock),
				new CVE202122986DetectorBootstrapModule(),
				new HttpClientModule.Builder().build())
				.injectMembers(this);
	}

	@After
	public void tearDown() throws IOException {
		mockWebServer.shutdown();
	}

	@Test
	public void detect_whenVulnerable_returnsVulnerability() throws IOException {
		mockWebResponse(CVE202122986VulnDetector.DETECTION_STRING);
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
																.setValue("CVE-2021-22986"))
												.setSeverity(Severity.HIGH)
												.setTitle("CVE-2021-22986")
												.setDescription("The iControl REST interface has an unauthenticated remote command execution vulnerability."))
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
