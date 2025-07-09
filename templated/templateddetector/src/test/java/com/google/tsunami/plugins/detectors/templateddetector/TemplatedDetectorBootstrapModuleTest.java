package com.google.tsunami.plugins.detectors.templateddetector;

import static com.google.common.truth.Truth.assertThat;

import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TemplatedDetectorBootstrapModuleTest {

  private static final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Test
  public void configureWithDisabledExampleDetector_doesNotloadExampleDetector() {
    var bootstrap = new TemplatedDetectorBootstrapModule();
    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock),
        new HttpClientModule.Builder().build(),
        FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
        bootstrap);

    assertThat(bootstrap.getDetectors()).doesNotContainKey("ExampleTemplated");
  }

  @Test
  public void configureForceLoad_loadsExampleDetector() {
    var bootstrap = new TemplatedDetectorBootstrapModule();
    bootstrap.setForceLoadDetectors(true);
    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock),
        new HttpClientModule.Builder().build(),
        FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
        bootstrap);

    assertThat(bootstrap.getDetectors()).containsKey("ExampleTemplated");
  }
}
