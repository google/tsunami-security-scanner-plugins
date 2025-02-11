/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.templateddetector;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.reflect.ClassPath;
import com.google.inject.Guice;
import com.google.testing.junit.testparameterinjector.TestParameterInjector;
import com.google.testing.junit.testparameterinjector.TestParameters;
import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
import com.google.testing.junit.testparameterinjector.TestParametersValuesProvider;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.templatedplugin.proto.tests.HttpTestAction;
import com.google.tsunami.templatedplugin.proto.tests.TemplatedPluginTests;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jspecify.annotations.Nullable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Dynamically generated tests for {@link TemplatedDetector}'s plugins. */
@RunWith(TestParameterInjector.class)
public final class TemplatedDetectorDynamicTest {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private Environment environment;
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;

  private static final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setupMockServers() throws IOException {
    environment = new Environment(false);
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    var baseUrl = "http://" + mockWebServer.getHostName() + ":" + mockWebServer.getPort() + "/";
    environment.set("T_NS_BASEURL", baseUrl);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  @TestParameters(valuesProvider = TestProvider.class)
  public void runTest(String pluginName, TemplatedPluginTests.Test testCase) {
    var detectors = getDetectorsForCase(testCase);

    if (!detectors.containsKey(pluginName)) {
      throw new IllegalArgumentException(
          "Plugin '"
              + pluginName
              + "' not found (ensure the tested_plugin field is set correctly).");
    }

    var detector = detectors.get(pluginName);
    switch (testCase.getAnyActionCase()) {
      case MOCK_HTTP_SERVER:
        forHttpAction(detector, testCase);
        break;
      default:
        throw new IllegalArgumentException("Unsupported action: " + testCase.getAnyActionCase());
    }
  }

  private final ImmutableMap<String, TemplatedDetector> getDetectorsForCase(
      TemplatedPluginTests.Test testCase) {
    // Inject the adequate callback server configuration.
    FakePayloadGeneratorModule.Builder payloadGeneratorModuleBuilder =
        FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom);

    if (testCase.getMockCallbackServer().getEnabled()) {
      payloadGeneratorModuleBuilder.setCallbackServer(mockCallbackServer);

      try {
        if (testCase.getMockCallbackServer().getHasInteraction()) {
          mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());
        } else {
          mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    // Inject dependencies and get the detectors.
    var bootstrap = new TemplatedDetectorBootstrapModule();
    bootstrap.setForceLoadDetectors(true);
    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock),
        new HttpClientModule.Builder().build(),
        payloadGeneratorModuleBuilder.build(),
        bootstrap);

    return bootstrap.getDetectors();
  }

  private final void forHttpAction(TemplatedDetector detector, TemplatedPluginTests.Test testCase) {
    ImmutableList<NetworkService> httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(
                    forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    prepareMockServer(ImmutableList.copyOf(testCase.getMockHttpServer().getMockResponsesList()));

    assertThat(detector).isNotNull();
    if (testCase.getExpectVulnerability()) {
      assertThat(detector.detect(targetInfo, httpServices).getDetectionReportsCount())
          .isEqualTo(httpServices.size());
    } else {
      assertThat(detector.detect(targetInfo, httpServices).getDetectionReportsCount()).isEqualTo(0);
    }
  }

  private final void prepareMockServer(ImmutableList<HttpTestAction.MockResponse> mockResponses) {
    var responseMap = mockResponses.stream().collect(toImmutableMap(r -> r.getUri(), r -> r));

    Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if (responseMap.containsKey(request.getPath())) {
              return dispatchResponse(request, responseMap.get(request.getPath()));
            }

            // Magic that matches any URI.
            if (responseMap.containsKey("TSUNAMI_MAGIC_ANY_URI")) {
              return dispatchResponse(request, responseMap.get("TSUNAMI_MAGIC_ANY_URI"));
            }

            // Magic that makes the server behave as an echo server.
            if (responseMap.containsKey("TSUNAMI_MAGIC_ECHO_SERVER")) {
              var content =
                  request.toString()
                      + "\n"
                      + request.getHeaders().toString()
                      + "\n"
                      + request.getUtf8Body();
              return new MockResponse().setBody(content);
            }

            return new MockResponse().setResponseCode(404);
          }
        };

    mockWebServer.setDispatcher(dispatcher);
  }

  private final MockResponse dispatchResponse(
      RecordedRequest request, HttpTestAction.MockResponse response) {
    // ensure the headers condition are met.
    if (response.getCondition().getHeadersCount() > 0) {
      for (var h : response.getCondition().getHeadersList()) {
        var expectedHeader = environment.substitute(h.getValue());
        var seenHeader = request.getHeader(h.getName());
        if (seenHeader == null || !expectedHeader.equals(seenHeader)) {
          logger.atInfo().log(
              "Header '%s', got:'%s' want:'%s', returning 404",
              h.getName(), seenHeader, expectedHeader);
          return new MockResponse().setResponseCode(404);
        }
      }
    }

    // ensure the body content condition are met.
    if (response.getCondition().getBodyContentCount() > 0) {
      for (var b : response.getCondition().getBodyContentList()) {
        if (!request.getUtf8Body().contains(b)) {
          logger.atInfo().log(
              "Body content did not match content condition with '%s', returning 404", b);
          return new MockResponse().setResponseCode(404);
        }
      }
    }

    return createResponse(response);
  }

  private final MockResponse createResponse(HttpTestAction.MockResponse testResponse) {
    var mock =
        new MockResponse()
            .setResponseCode(testResponse.getStatus())
            .setBody(testResponse.getBodyContent());
    testResponse.getHeadersList().forEach(h -> mock.addHeader(h.getName(), h.getValue()));
    return mock;
  }

  static final class TestProvider extends TestParametersValuesProvider {
    @Override
    public ImmutableList<TestParametersValues> provideValues(Context context) {
      return getResourceNames().stream()
          .map(TestProvider::loadPlugin)
          .filter(plugin -> plugin != null)
          .flatMap(plugin -> parametersForPlugin(plugin).stream())
          .collect(toImmutableList());
    }

    private static ImmutableList<TestParametersValues> generateCommonTests(String pluginName) {
      // Echo server test: plugins should never return a vulnerability when the response just
      // contains the request.
      var testName = pluginName + ", autogenerated_whenEchoServer_returnsFalse";
      return ImmutableList.of(
          TestParametersValues.builder()
              .name(testName)
              .addParameter("pluginName", pluginName)
              .addParameter(
                  "testCase",
                  TemplatedPluginTests.Test.newBuilder()
                      .setName(testName)
                      .setExpectVulnerability(false)
                      .setMockHttpServer(
                          HttpTestAction.newBuilder()
                              .addMockResponses(
                                  HttpTestAction.MockResponse.newBuilder()
                                      .setUri("TSUNAMI_MAGIC_ECHO_SERVER")))
                      .build())
              .build());
    }

    private static ImmutableList<TestParametersValues> parametersForPlugin(
        TemplatedPluginTests pluginTests) {
      var pluginName = pluginTests.getConfig().getTestedPlugin();

      if (pluginTests.getConfig().getDisabled()) {
        logger.atWarning().log("Plugin '%s' tests are disabled.", pluginName);
        return ImmutableList.of();
      }

      var testsBuilder = ImmutableList.<TestParametersValues>builder();
      // Inject tests that are common to all plugins.
      testsBuilder.addAll(generateCommonTests(pluginName));

      // Tests defined in the plugin test file.
      pluginTests.getTestsList().stream()
          .map(
              t ->
                  TestParametersValues.builder()
                      .name(pluginName + ", " + t.getName())
                      .addParameter("pluginName", pluginName)
                      .addParameter("testCase", t)
                      .build())
          .forEach(testsBuilder::add);

      return testsBuilder.build();
    }

    @SuppressWarnings("ProtoParseWithRegistry")
    private static @Nullable TemplatedPluginTests loadPlugin(String resourceName) {
      try {
        URL url = Resources.getResource(resourceName);
        var byteStream = Resources.toByteArray(url);
        return TemplatedPluginTests.parseFrom(byteStream);
      } catch (IOException e) {
        logger.atSevere().withCause(e).log("Failed to read plugin: %s", resourceName);
        return null;
      }
    }

    private static ImmutableList<String> getResourceNames() {
      ImmutableList.Builder<String> resourceNames = ImmutableList.builder();
      ClassPath classPath = null;

      try {
        classPath = ClassPath.from(ClassLoader.getSystemClassLoader());
      } catch (IOException e) {
        logger.atSevere().withCause(e).log("Failed to dynamically load the list of plugins.");
        return ImmutableList.of();
      }

      for (var resource : classPath.getResources()) {
        var resourceName = resource.getResourceName();
        if (!resourceName.contains("templateddetector/plugins/")) {
          continue;
        }

        if (!resourceName.endsWith("_test.binarypb")) {
          continue;
        }

        resourceNames.add(resourceName);
      }

      return resourceNames.build();
    }
  }
}
