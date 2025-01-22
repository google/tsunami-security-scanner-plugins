package com.google.tsunami.plugins.detectors.templateddetector.actions;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.templateddetector.ActionRunner;
import com.google.tsunami.plugins.detectors.templateddetector.Environment;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.templatedplugin.proto.HttpAction;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import java.io.IOException;

/** HttpActionRunner is an ActionRunner that runs HTTP request actions. */
public final class HttpActionRunner implements ActionRunner {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final HttpClient httpClient;
  private final boolean debug;

  public HttpActionRunner(HttpClient httpClient, boolean debug) {
    this.httpClient = checkNotNull(httpClient);
    this.debug = debug;
  }

  @Override
  public boolean run(NetworkService service, PluginAction action, Environment environment) {
    if (!action.hasHttpRequest()) {
      throw new IllegalArgumentException(
          String.format(
              "Action '%s' is not an HTTP action. Is the plugin misconfigured?", action.getName()));
    }

    return action.getHttpRequest().getUriList().stream()
        .anyMatch(uri -> run(service, action, environment, uri));
  }

  private boolean run(
      NetworkService service, PluginAction action, Environment environment, String uri) {
    // Remove leading slash if present as it will be added later and substitute variables.
    uri = environment.substitute(uri);
    uri = uri.startsWith("/") ? uri.substring(1) : uri;

    HttpAction httpAction = action.getHttpRequest();
    String targetUrl = NetworkServiceUtils.buildWebApplicationRootUrl(service) + uri;

    if (httpAction.getMethod() == HttpAction.HttpMethod.METHOD_UNSPECIFIED) {
      throw new IllegalArgumentException(
          String.format(
              "Action '%s' has an invalid HTTP method: %s",
              action.getName(), httpAction.getMethod()));
    }

    HttpRequest.Builder requestBuilder =
        HttpRequest.builder()
            .setUrl(targetUrl)
            .setMethod(HttpMethod.valueOf(httpAction.getMethod().toString()));
    HttpHeaders.Builder headersBuilder = HttpHeaders.builder();
    httpAction.getHeadersList()
        .forEach(
            header ->
                headersBuilder.addHeader(
                    header.getName(), environment.substitute(header.getValue())));
    requestBuilder.setHeaders(headersBuilder.build());

    if (!httpAction.getData().isEmpty()) {
      requestBuilder.setRequestBody(
          ByteString.copyFromUtf8(environment.substitute(httpAction.getData())));
    }

    HttpResponse response;
    HttpRequest request = requestBuilder.build();

    if (this.debug) {
      logger.atInfo().log("Sending request: %s\n", request);
      logger.atInfo().log(
          "Request body: %s", request.requestBody().orElse(ByteString.EMPTY).toStringUtf8());
    }

    try {
      response = httpClient.send(requestBuilder.build());
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
          "Action '%s' failed with exception: %s", action.getName(), e.getMessage());
      return false;
    }

    if (this.debug) {
      logger.atInfo().log("Received response: %s", response);
      logger.atInfo().log("Response body: %s", response.bodyString().orElse(""));
    }

    if (httpAction.getResponse().getHttpStatus() != 0) {
      if (httpAction.getResponse().getHttpStatus() != response.status().code()) {
        return false;
      }
    }

    return checkExpectations(response, httpAction, environment)
        && performExtractions(response, httpAction, environment);
  }

  private boolean checkExpectation(
      HttpResponse response,
      HttpAction.HttpResponse.Expectation expectation,
      Environment environment) {
    var expectContains = environment.substitute(expectation.getContains());
    switch (expectation.getExpectationCase()) {
      case BODY:
        return response.bodyString().orElse("").contains(expectContains);
      case HEADER:
        var headerName = environment.substitute(expectation.getHeader().getName());
        var header = response.headers().get(headerName);
        return header.orElse("").contains(expectContains);
      default:
        throw new IllegalArgumentException(
            String.format(
                "Invalid expectation type: %s (did you specify from_body or from_header?)",
                expectation.getExpectationCase()));
    }
  }

  private boolean checkExpectations(
      HttpResponse response, HttpAction httpAction, Environment environment) {
    switch (httpAction.getResponse().getExpectationsCase()) {
      case EXPECTATIONS_NOT_SET:
        return true;
      case EXPECT_ALL:
        return httpAction.getResponse().getExpectAll().getConditionsList().stream()
            .allMatch(expectation -> checkExpectation(response, expectation, environment));
      case EXPECT_ANY:
        return httpAction.getResponse().getExpectAny().getConditionsList().stream()
            .anyMatch(expectation -> checkExpectation(response, expectation, environment));
    }

    throw new IllegalArgumentException(
        String.format(
            "Invalid expectations type: %s", httpAction.getResponse().getExpectationsCase()));
  }

  private boolean performExtraction(
      HttpResponse response, HttpAction.HttpResponse.Extract extract, Environment environment) {
    var variableName = extract.getVariableName();
    var regexp = environment.substitute(extract.getRegexp());

    switch (extract.getExtractCase()) {
      case FROM_BODY:
        return environment.extract(response.bodyString().orElse(""), variableName, regexp);
      case FROM_HEADER:
        var headerName = environment.substitute(extract.getFromHeader().getName());
        return response.headers().getAll(headerName).stream()
            .filter(header -> !header.isEmpty())
            .anyMatch(header -> environment.extract(header, variableName, regexp));
      default:
        throw new IllegalArgumentException(
            String.format(
                "Invalid extraction type: %s (did you specify from_body or from_header?)",
                extract.getExtractCase()));
    }
  }

  private boolean performExtractions(
      HttpResponse response, HttpAction httpAction, Environment environment) {
    switch (httpAction.getResponse().getExtractionsCase()) {
      case EXTRACTIONS_NOT_SET:
        return true;
      case EXTRACT_ALL:
        return httpAction.getResponse().getExtractAll().getPatternsList().stream()
            .allMatch(extract -> performExtraction(response, extract, environment));
      case EXTRACT_ANY:
        return httpAction.getResponse().getExtractAny().getPatternsList().stream()
            .anyMatch(extract -> performExtraction(response, extract, environment));
    }

    throw new IllegalArgumentException(
        String.format(
            "Invalid extraction type: %s", httpAction.getResponse().getExtractionsCase()));
  }
}
