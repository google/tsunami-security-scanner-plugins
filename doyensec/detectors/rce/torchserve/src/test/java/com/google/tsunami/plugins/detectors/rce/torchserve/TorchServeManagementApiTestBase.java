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

import java.io.IOException;
import java.time.Instant;

import javax.inject.Inject;

import org.junit.After;
import org.junit.Before;

import com.google.inject.*;
import com.google.inject.Module;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;

import okhttp3.mockwebserver.MockWebServer;

public abstract class TorchServeManagementApiTestBase {
    @Inject @Named("target")
    protected MockWebServer mockTorchServe;

    protected final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

    // These should be defined in the subclass as needed
    //@Inject
    //protected TorchServeManagementApiDetector detector;

    //@Inject
    //protected TorchServeExploiter exploiter;

    private static class CustomTestModule extends AbstractModule {
        private FakeUtcClock fakeUtcClock;

        CustomTestModule(FakeUtcClock fakeUtcClock) {
            this.fakeUtcClock = fakeUtcClock;
        }

        @Override
        protected void configure() {
            // Guice modules provide by Tsunami
            install(new HttpClientModule.Builder().build());
            install(new FakeUtcClockModule(fakeUtcClock));

            bind(MockWebServer.class)
                .annotatedWith(Names.named("target"))
                .toInstance(new MockWebServer());

            FakePayloadGeneratorModule fakePayloadGeneratorModule = FakePayloadGeneratorModule.builder().build();
            install(fakePayloadGeneratorModule);

            // Our detector and exploiter
            bind(TorchServeRandomUtils.class)
                .to(MockTorchServeRandomUtils.class);
            bind(TorchServeManagementApiDetector.class);
            bind(TorchServeExploiter.class);
            bind(TorchServeManagementAPIExploiterWebServer.class)
                .to(MockTorchServeManagementApiExploiterWebServer.class);
        }
    }

    protected Module getBaseModule() {
        return new CustomTestModule(fakeUtcClock);
    }

    // Override this in subclasses for custom setup
    protected void onTestExecution() throws IOException {
        // Do nothing
    }

    @Before
    public void setUp() throws IOException {
        Injector baseInjector = Guice.createInjector(getBaseModule());
        baseInjector.injectMembers(this);
//        this.mockTorchServe.start();
        onTestExecution();
    }

    @After
    public void tearDown() throws IOException {
//        this.mockTorchServe.shutdown();
    }
}
