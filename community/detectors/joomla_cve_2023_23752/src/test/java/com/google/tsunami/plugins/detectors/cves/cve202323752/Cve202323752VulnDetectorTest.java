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
package com.google.tsunami.plugins.detectors.cves.cve202323752;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.*;
import static com.google.tsunami.plugins.detectors.cves.cve202323752.Cve202323752VulnDetector.DETECTION_STRING_1;
import static com.google.tsunami.plugins.detectors.cves.cve202323752.Cve202323752VulnDetector.DETECTION_STRING_2;
import static com.google.tsunami.plugins.detectors.cves.cve202323752.Cve202323752VulnDetector.DETECTION_STRING_BY_STATUS;
import static com.google.tsunami.plugins.detectors.cves.cve202323752.Cve202323752VulnDetector.VULNERABLE_PATH;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import java.io.*;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202323752VulnDetector}. */
@RunWith(JUnit4.class)
public final class Cve202323752VulnDetectorTest {

    private final FakeUtcClock fakeUtcClock =
        FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

    @Inject private Cve202323752VulnDetector detector;

    private final MockWebServer mockWebServer = new MockWebServer();
    ;

    private NetworkService joomlaservice;
    private TargetInfo targetInfo;

    @Before
    public void setUp() throws IOException {
        mockWebServer.start();
        mockWebServer.url("/" + VULNERABLE_PATH);
        Guice.createInjector(
                new FakeUtcClockModule(fakeUtcClock),
                new HttpClientModule.Builder().build(),
                new Cve202323752DetectorBootstrapModule())
            .injectMembers(this);

        joomlaservice =
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setSoftware(Software.newBuilder().setName("joomla 4.2.6-php8.0"))
                .setServiceName("http")
                .build();

        targetInfo =
            TargetInfo.newBuilder()
                .addNetworkEndpoints(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .build();
    }

    @After
    public void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    public void detect_whenVulnerable_returnsVulnerability()
        throws IOException, InterruptedException {
        MockResponse response =
            new MockResponse()
                .addHeader("Content-Type", "application/json; charset=utf-8")
                .setBody(DETECTION_STRING_2 + "\n" + DETECTION_STRING_1)
                .setResponseCode(DETECTION_STRING_BY_STATUS);
        mockWebServer.enqueue(response);

        DetectionReportList mockWebServer_detectionReports =
            detector.detect(targetInfo, ImmutableList.of(joomlaservice));

        DetectionReport expected_detectionReport =
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(joomlaservice)
                .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2023_23752"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Joomla unauthorized access to webservice endpoints")
                        .setDescription(
                            "CVE-2023-23752: An improper access check allows unauthorized access to"
                                + " webservice endpoints")
                        .setRecommendation("Upgrade to version 4.2.8 and higher")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText(
                                            "attacker can get critical information of database and webserver like passwords by this vulnerability"))))
                .build();

        assertThat(mockWebServer_detectionReports.getDetectionReportsList())
            .containsExactly(expected_detectionReport);
    }

    @Test
    public void detect_whenNotVulnerable_returnsNoVulnerability() throws IOException {
        mockWebServer.url("/notexistpath123321");
        MockResponse response =
            new MockResponse()
                .addHeader("Content-Type", "application/json; charset=utf-8")
                .setBody("NotExistDetectionString")
                .setResponseCode(200);
        mockWebServer.enqueue(response);
        DetectionReportList mockWebServer_detectionReports =
            detector.detect(targetInfo, ImmutableList.of(joomlaservice));
        assert (mockWebServer_detectionReports.getDetectionReportsList().isEmpty());
    }
}