/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve2026111497outbound;

import static com.google.common.truth.Truth.assertThat;

import com.google.inject.Binding;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.TypeLiteral;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.TsunamiPlugin;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import java.time.Instant;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026111497OutboundDetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public final class Cve2026111497OutboundDetectorBootstrapModuleTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-01-01T00:00:00.00Z"));

  @Test
  public void configurePlugin_registersCve2026111497OutboundDetector() {
    Injector injector =
        Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().build(),
            new Cve2026111497OutboundDetectorBootstrapModule());

    List<Binding<TsunamiPlugin>> bindings =
        injector.findBindingsByType(TypeLiteral.get(TsunamiPlugin.class));

    assertThat(bindings).hasSize(1);
    assertThat(bindings.get(0).getProvider().get())
        .isInstanceOf(Cve2026111497OutboundDetector.class);
  }
}
