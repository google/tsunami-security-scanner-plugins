package com.google.tsunami.plugins.detectors.rce.torchserve;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.inject.Inject;

import org.junit.After;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import com.google.inject.util.Modules;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;

import okhttp3.mockwebserver.MockWebServer;

public abstract class TorchServeManagementApiTestBaseWithCallbackServer extends TorchServeManagementApiTestBase {
    @Inject @Named("callback")
    protected MockWebServer mockCallbackServer;

    private final SecureRandom testSecureRandom = new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, (byte) 0xFF);
        }
    };

    @Override
    protected Module getBaseModule() {
        Module baseModule = super.getBaseModule();
        Module callbackModule = new AbstractModule() {
            @Override
            protected void configure() {
                MockWebServer mockCallbackServerInstance = new MockWebServer();
                FakePayloadGeneratorModule fakePayloadGeneratorModule = FakePayloadGeneratorModule.builder()
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
