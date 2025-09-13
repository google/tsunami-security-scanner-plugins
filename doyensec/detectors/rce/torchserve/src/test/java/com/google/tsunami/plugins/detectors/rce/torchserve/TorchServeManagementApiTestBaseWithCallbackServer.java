/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.torchserve;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import com.google.inject.util.Modules;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;

public abstract class TorchServeManagementApiTestBaseWithCallbackServer
    extends TorchServeManagementApiTestBase {
  @Inject
  @Named("callback")
  protected MockWebServer mockCallbackServer;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Override
  protected Module getBaseModule() {
    Module baseModule = super.getBaseModule();
    Module callbackModule =
        new AbstractModule() {
          @Override
          protected void configure() {
            MockWebServer mockCallbackServerInstance = new MockWebServer();
            FakePayloadGeneratorModule fakePayloadGeneratorModule =
                FakePayloadGeneratorModule.builder()
                    .setCallbackServer(mockCallbackServerInstance)
                    .setSecureRng(testSecureRandom)
                    .build();
            install(fakePayloadGeneratorModule);
            bind(MockWebServer.class)
                .annotatedWith(Names.named("callback"))
                .toInstance(mockCallbackServerInstance);
          }
        };
    return Modules.override(baseModule).with(callbackModule);
  }

  @After
  public void tearDown() throws IOException {
    super.tearDown();
    this.mockCallbackServer.shutdown();
  }
}
