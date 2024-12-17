package com.google.tsunami.plugins.papercut;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.flogger.GoogleLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.proto.NetworkService;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A helper class for managing jsessionId based web session. */
public final class PapercutNgMfHelper {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final NetworkService networkService;
  private final HttpClient httpClient;
  public String jsessionId = "";
  private String rootUrl = "";
  private String baseAppUrl = "";
  private HttpHeaders headers;
  private String previousUrl = "";

  PapercutNgMfHelper(NetworkService networkService, HttpClient httpClient) {
    this.networkService = checkNotNull(networkService);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    this.baseAppUrl = this.rootUrl + "app";
    buildHeaders(false);
  }

  // this doesn't need to be public, but leaving it as such just-in-case
  public void updateJsessionId(HttpResponse response) {
    String setCookiesHeader = response.headers().get("Set-Cookie").orElse("");
    if (!setCookiesHeader.isEmpty()) {
      Matcher jsessionIdMatcher =
          Pattern.compile("JSESSIONID=[a-zA-Z0-9.]+;", Pattern.CASE_INSENSITIVE)
              .matcher(setCookiesHeader);
      if (jsessionIdMatcher.find()) {
        jsessionId = jsessionIdMatcher.group();
      }
    }
  }

  public void buildHeaders(boolean isPostRequest) {
    HttpHeaders.Builder headers = HttpHeaders.builder();

    // Default headers
    headers.addHeader("Origin", this.rootUrl);
    headers.addHeader("Accept", "*/*");

    // Add content-type helper
    if (isPostRequest) {
      headers.addHeader("Content-Type", "application/x-www-form-urlencoded");
    }

    // The initial request won't have a referer to use, so don't set it
    if (!this.previousUrl.isEmpty()) {
      headers.addHeader("Referer", this.previousUrl);
    }

    // Add or update the JSESSION_ID if a value is present
    if (!jsessionId.isEmpty()) {
      headers.addHeader("Cookie", jsessionId);
    }

    this.headers = headers.build();
  }

  @CanIgnoreReturnValue
  public HttpResponse sendGetRequest(String path) {
    buildHeaders(false); // Rebuild the headers
    HttpRequest request = HttpRequest.get(baseAppUrl + "?" + path).setHeaders(headers).build();
    HttpResponse response = null;
    try {
      response = httpClient.send(request, this.networkService);
      updateJsessionId(response); // Update JSESSION_ID if needed
      previousUrl = baseAppUrl + "?" + path;
    } catch (Exception err) {
      logger.atWarning().withCause(err).log();
    }
    return response;
  }

  @CanIgnoreReturnValue
  public HttpResponse sendPostRequest(String bodyContent) {
    buildHeaders(true); // Rebuild the headers
    HttpRequest request =
        HttpRequest.post(baseAppUrl)
            .setHeaders(headers)
            .setRequestBody(ByteString.copyFrom(bodyContent, StandardCharsets.UTF_8))
            .build();

    HttpResponse response = null;
    try {
      response = httpClient.send(request, networkService);
      this.updateJsessionId(response); // Update JSESSION_ID if needed
      previousUrl = baseAppUrl;
    } catch (Exception err) {
      logger.atWarning().withCause(err).log();
    }
    return response;
  }

  public String buildParameterString(HashMap<String, String> params) {
    StringBuilder result = new StringBuilder();
    boolean first = true;
    for (Map.Entry<String, String> entry : params.entrySet()) {
      if (first) {
        first = false;
      } else {
        result.append("&");
      }
      result.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
      result.append("=");
      result.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
    }
    return result.toString();
  }

  public void changeSettingForPayload(String settingName, Boolean enable) {
    HashMap<String, String> settingNav = new HashMap<>();
    settingNav.put("service", "direct/1/ConfigEditor/quickFindForm");
    settingNav.put("sp", "S0");
    settingNav.put("Form0", "$TextField,doQuickFind,clear");
    settingNav.put("$TextField", settingName);
    settingNav.put("doQuickFind", "Go");

    HashMap<String, String> settingAction = new HashMap<>();
    settingAction.put("service", "direct/1/ConfigEditor/$Form");
    settingAction.put("sp", "S1");
    settingAction.put("Form1", "$TextField$0,$Submit,$Submit$0");
    settingAction.put("$TextField$0", (enable ? "Y" : "N"));
    settingAction.put("$Submit", "Update");

    sendPostRequest(buildParameterString(settingNav));
    sendPostRequest(buildParameterString(settingAction));
  }
}
