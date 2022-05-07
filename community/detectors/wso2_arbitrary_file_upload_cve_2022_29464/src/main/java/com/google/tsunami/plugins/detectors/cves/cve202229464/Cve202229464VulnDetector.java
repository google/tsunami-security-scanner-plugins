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
package com.google.tsunami.plugins.detectors.cves.cve202229464;

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
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Random;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.*;
import static com.google.tsunami.common.net.http.HttpRequest.post;

/** A {@link VulnDetector} that detects the CVE-2022-29464 vulnerability. */
// PluginInfo tells Tsunami scanning engine basic information about your plugin.
@PluginInfo(
        // Which type of plugin this is.
        type = PluginType.VULN_DETECTION,
        // A human readable name of your plugin.
        name = "Cve202229464VulnDetector",
        // Current version of your plugin.
        version = "0.1",
        // Detailed description about what this plugin does.
        description = "WSO2 API Manager 2.2.0, up to 4.0.0," +
                "WSO2 Identity Server 5.2.0, up to 5.11.0," +
                "WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, 5.6.0," +
                "WSO2 Identity Server as Key Manager 5.3.0, up to 5.11.0," +
                "WSO2 Enterprise Integrator 6.2.0, up to 6.6.0," +
                "WSO2 Open Banking AM 1.4.0, up to 2.0.0," +
                "WSO2 Open Banking KM 1.4.0, up to 2.0.0 contains a arbitrary file upload vulnerability." +
                "Due to improper validation of user input, a malicious actor could upload an arbitrary file to a user controlled location of the server. By leveraging the arbitrary file upload vulnerability, it is further possible to gain remote code execution on the server.",
        // Author of this plugin.
        author = "r00tuser",
        // How should Tsunami scanner bootstrap your plugin.
        bootstrapModule = Cve202229464VulnDetectorBootstrapModule.class)
// Optionally, each VulnDetector can be annotated by service filtering annotations. For example, if
// the VulnDetector should only be executed when the scan target is running Jenkins, then add the
// following @ForSoftware annotation.
// @ForSoftware(name = "Jenkins")
public final class Cve202229464VulnDetector implements VulnDetector {
    private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

    private final HttpClient httpClient;

    private final Clock utcClock;

    private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("^1\\.\\d{15,16}E12$");

    // Tsunami scanner relies heavily on Guice framework. So all the utility dependencies of your
    // plugin must be injected through the constructor of the detector. Here the UtcClock is provided
    // by the scanner.
    @Inject
    Cve202229464VulnDetector(HttpClient httpClient, @UtcClock Clock utcClock) {
        this.httpClient = checkNotNull(httpClient);
        this.utcClock = checkNotNull(utcClock);
    }

    // This is the main entry point of your VulnDetector. Both parameters will be populated by the
    // scanner. targetInfo contains the general information about the scan target. matchedServices
    // parameter contains all the network services that matches the service filtering annotations
    // mentioned earlier. If no filtering annotations added, then matchedServices parameter contains
    // all exposed network services on the scan target.
    @Override
    public DetectionReportList detect(
            TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
        logger.atInfo().log("CVE-2022-29464 starts detecting.");

        // An example implementation for a VulnDetector.
        return DetectionReportList.newBuilder()
                .addAllDetectionReports(
                        matchedServices.stream()
                                .filter(NetworkServiceUtils::isWebService)
                                // Check individual NetworkService whether it is vulnerable.
                                .filter(this::isServiceVulnerable)
                                // Build DetectionReport message for vulnerable services.
                                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                                .collect(toImmutableList()))
                .build();
    }

    // Checks whether a given network service is vulnerable. Real detection logic implemented here.
    private boolean isServiceVulnerable(NetworkService networkService) {
        String targetUploadUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) +
                "fileupload/tools";
        String vulFileName = getRandomString(6);
        try {
            HttpResponse response = httpClient.send(
                    post(targetUploadUri)
                            .setHeaders(
                                    HttpHeaders.builder()
                                            .addHeader(CONTENT_TYPE, "multipart/form-data; boundary=----WebKitFormBoundaryVulnTest")
                                            .addHeader(ACCEPT, "text/html")
                                            .addHeader(REFERER, NetworkServiceUtils.buildWebApplicationRootUrl(networkService))
                                            .addHeader(CONNECTION, "close")
                                            .build())
                            .setRequestBody(ByteString.copyFrom("------WebKitFormBoundaryVulnTest\n" +
                                    "        Content-Disposition: form-data; name=\""+ vulFileName +"\"; filename=\""+ vulFileName +"\"\n\n" +
                                    "        TSUNAMI_COMMUNITY_VUL_TEST\n" +
                                    "        ------WebKitFormBoundaryVulnTest", "utf-8"))
                            .build(),
                    networkService);


            if (response.status().code() == 200 && VULNERABILITY_RESPONSE_PATTERN.matcher(response.bodyString().get()).find()) {
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
                                                .setValue("CVE-2022-29464"))
                                .setSeverity(Severity.CRITICAL)
                                .setTitle("WSO2 Unrestricted Arbitrary File Upload CVE-2022-29464")
                                .setDescription("WSO2 API Manager 2.2.0, up to 4.0.0," +
                                        "WSO2 Identity Server 5.2.0, up to 5.11.0," +
                                        "WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, 5.6.0," +
                                        "WSO2 Identity Server as Key Manager 5.3.0, up to 5.11.0," +
                                        "WSO2 Enterprise Integrator 6.2.0, up to 6.6.0," +
                                        "WSO2 Open Banking AM 1.4.0, up to 2.0.0," +
                                        "WSO2 Open Banking KM 1.4.0, up to 2.0.0 contains a arbitrary file upload vulnerability." +
                                        "Due to improper validation of user input, a malicious actor could upload an arbitrary file to a user controlled location of the server. By leveraging the arbitrary file upload vulnerability, it is further possible to gain remote code execution on the server.")
                                )
                .build();
    }

    private String getRandomString(int length){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        SecureRandom random= new SecureRandom();
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }
}
