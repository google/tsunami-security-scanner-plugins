package com.google.tsunami.plugins.papercut;

import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.proto.NetworkService;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkNotNull;

public class PapercutNGMFHelper {

    private String root_url = "";
    private String base_app_url = "";
    public String JSESSION_ID = "";
    private NetworkService networkService;
    private HttpHeaders headers;
    private GoogleLogger logger;
    private HttpClient httpClient;
    private String previousUrl = "";

    PapercutNGMFHelper(
            NetworkService networkService,
            GoogleLogger logger,
            HttpClient httpClient
    ) {
        this.networkService = checkNotNull(networkService);
        this.logger = checkNotNull(logger);
        this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
        this.root_url = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
        this.base_app_url = this.root_url + "app";
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
                JSESSION_ID = jsessionIdMatcher.group();
            }
        }
    }

    public void buildHeaders(boolean isPostRequest) {
        HttpHeaders.Builder headers = HttpHeaders.builder();

        // Default headers
        headers.addHeader("Origin", this.root_url);
        headers.addHeader("Accept", "*/*");

        // Add content-type helper
        if (isPostRequest) headers.addHeader("Content-Type", "application/x-www-form-urlencoded");

        // The initial request won't have a referer to use, so don't set it
        if(!this.previousUrl.isEmpty()) headers.addHeader("Referer", this.previousUrl);

        // Add or update the JSESSION_ID if a value is present
        if (!JSESSION_ID.isEmpty())  headers.addHeader("Cookie", JSESSION_ID);

        this.headers = headers.build();
    }

    public HttpResponse sendGetRequest(String path) {
        buildHeaders(false); // Rebuild the headers
        HttpRequest request = HttpRequest.get(this.base_app_url + "?" + path).setHeaders(this.headers).build();
        HttpResponse response = null;
        try {
            response = this.httpClient.send(request, this.networkService);
            this.updateJsessionId(response); // Update JSESSION_ID if needed
            this.previousUrl = (this.base_app_url + "?" + path);
        } catch (Exception err) {
            logger.atWarning().withCause(err).log();
        }
        return response;
    }

    public HttpResponse sendPostRequest(String bodyContent) {
        buildHeaders(true); // Rebuild the headers
        HttpRequest request = HttpRequest.post(this.base_app_url)
                .setHeaders(this.headers)
                .setRequestBody(ByteString.copyFrom(bodyContent, StandardCharsets.UTF_8))
                .build();

        HttpResponse response = null;
        try {
            response = this.httpClient.send(request, this.networkService);
            this.updateJsessionId(response); // Update JSESSION_ID if needed
            this.previousUrl = (this.base_app_url);
        } catch (Exception err) {
            logger.atWarning().withCause(err).log();
        }
        return response;
    }

    public String buildParameterString(HashMap<String, String> params) {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (first) first = false;
            else result.append("&");
            result.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        return result.toString();
    }

    public void changeSettingForPayload(String settingName, Boolean enable) {
        HashMap<String, String> settingNav = new HashMap<String, String>();
        settingNav.put("service", "direct/1/ConfigEditor/quickFindForm");
        settingNav.put("sp", "S0");
        settingNav.put("Form0", "$TextField,doQuickFind,clear");
        settingNav.put("$TextField", settingName);
        settingNav.put("doQuickFind", "Go");

        HashMap<String, String> settingAction = new HashMap<String, String>();
        settingAction.put("service", "direct/1/ConfigEditor/$Form");
        settingAction.put("sp", "S1");
        settingAction.put("Form1", "$TextField$0,$Submit,$Submit$0");
        settingAction.put("$TextField$0", ( enable ? "Y" : "N" ));
        settingAction.put("$Submit", "Update");

        sendPostRequest(buildParameterString(settingNav));
        sendPostRequest(buildParameterString(settingAction));
    }
}
