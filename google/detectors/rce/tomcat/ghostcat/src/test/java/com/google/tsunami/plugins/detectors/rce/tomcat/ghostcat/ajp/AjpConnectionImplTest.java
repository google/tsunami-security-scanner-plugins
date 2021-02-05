/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Unit tests for {@link AjpConnectionImpl}. */
@RunWith(JUnit4.class)
public class AjpConnectionImplTest {
  private static final String REQ_URI = "/manager/xxxxx.jsp";
  private static final String PATH = "/WEB-INF/web.xml";

  private static final byte[] VALID_RESPONSE = {
      // AJP13_END_RESPONSE (5)
      'A', 'B', // magic
      0, 2, // size
      5, // packet prefix
      1, // reuse
  };

  @Rule public MockitoRule rule = MockitoJUnit.rule();

  @Mock Socket socketMock;

  @Inject AjpConnection.Factory ajpConnectionFactory;

  @Before
  public void setUp() throws IOException {
    Guice.createInjector(
            new FactoryModuleBuilder()
                .implement(AjpConnection.class, AjpConnectionImpl.class)
                .build(AjpConnection.Factory.class),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(Socket.class).toInstance(socketMock);
              }
            })
        .injectMembers(this);

    when(socketMock.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socketMock.getInputStream()).thenReturn(new ByteArrayInputStream(VALID_RESPONSE));
  }

  @Test
  public void performGhostcat_always_establishesConnection() throws IOException {
    ajpConnectionFactory.create("1.1.1.1", 80).performGhostcat(REQ_URI, PATH);

    verify(socketMock, times(1)).connect(new InetSocketAddress("1.1.1.1", 80));
  }

  @Test
  public void performGhostcat_always_writesThenReads() throws IOException {
    AtomicInteger step = new AtomicInteger(0);
    when(socketMock.getOutputStream())
        .thenAnswer(
            invocation -> {
              assertThat(step.incrementAndGet()).isEqualTo(1);
              return new ByteArrayOutputStream();
            });
    when(socketMock.getInputStream())
        .thenAnswer(
            invocation -> {
              assertThat(step.incrementAndGet()).isEqualTo(2);
              return new ByteArrayInputStream(VALID_RESPONSE);
            });

    ajpConnectionFactory.create("1.1.1.1", 80).performGhostcat(REQ_URI, PATH);

    assertThat(step.get()).isEqualTo(2);
  }

  @Test
  public void performGhostcat_whenSocketConnectThrows_rethrowsException() throws IOException {
    IOException ioException = new IOException("failed connection");
    doThrow(ioException).when(socketMock).connect(any());

    IOException exception =
        assertThrows(
            IOException.class,
            () -> ajpConnectionFactory.create("1.1.1.1", 80).performGhostcat(REQ_URI, PATH));

    assertThat(exception).isSameInstanceAs(ioException);
  }
}
