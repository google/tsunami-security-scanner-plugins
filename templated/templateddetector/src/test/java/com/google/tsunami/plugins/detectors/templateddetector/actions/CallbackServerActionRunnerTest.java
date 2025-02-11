package com.google.tsunami.plugins.detectors.templateddetector.actions;

import static com.google.common.truth.Truth.assertThat;

import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.templateddetector.Environment;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.templatedplugin.proto.CallbackServerAction;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CallbackServerActionRunnerTest {
  private CallbackServerActionRunner runner;
  private Environment environment;
  private MockWebServer mockCallbackServer;
  private NetworkService service;

  @Inject private TcsClient tcsClient;

  private static final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setup() {
    this.environment = new Environment(false);
    this.environment.set("T_CBS_SECRET", "irrelevant");
    this.service = NetworkService.getDefaultInstance();
  }

  @Before
  public void setupMockHttp() {
    this.mockCallbackServer = new MockWebServer();
  }

  @After
  public void tearMockHttp() throws IOException {
    this.mockCallbackServer.shutdown();
  }

  @Test
  public void checkAction_whenCallbackServerDisabled_returnsFalse() throws IOException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setCallbackServer(
                CallbackServerAction.newBuilder()
                    .setActionType(CallbackServerAction.ActionType.CHECK))
            .build();

    setupCallbackServer(false, false);

    assertThat(runner.run(this.service, action, this.environment)).isFalse();
  }

  @Test
  public void checkAction_whenCallbackServerReturnsFalse_returnsFalse() throws IOException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setCallbackServer(
                CallbackServerAction.newBuilder()
                    .setActionType(CallbackServerAction.ActionType.CHECK))
            .build();

    setupCallbackServer(true, false);

    assertThat(runner.run(this.service, action, this.environment)).isFalse();
    assertThat(this.mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void checkAction_whenCallbackServerReturnsTrue_returnsTrue() throws IOException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setCallbackServer(
                CallbackServerAction.newBuilder()
                    .setActionType(CallbackServerAction.ActionType.CHECK))
            .build();

    setupCallbackServer(true, true);

    assertThat(runner.run(this.service, action, this.environment)).isTrue();
    assertThat(this.mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  private final void setupCallbackServer(boolean enabled, boolean response) throws IOException {
    FakePayloadGeneratorModule.Builder payloadGeneratorModuleBuilder =
        FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom);

    if (enabled) {
      payloadGeneratorModuleBuilder.setCallbackServer(mockCallbackServer);

      if (response) {
        mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());
      } else {
        mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());
      }
    }

    Guice.createInjector(
            new HttpClientModule.Builder().build(), payloadGeneratorModuleBuilder.build())
        .injectMembers(this);
    this.runner = new CallbackServerActionRunner(tcsClient, false);
  }
}
