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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.composer;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TransportProtocol;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WeakCredentialComposer}. */
@RunWith(JUnit4.class)
public final class WeakCredentialsComposerTest {

  private static final ImmutableList<TestCredential> TEST_CREDENTIALS =
      ImmutableList.of(
          TestCredential.create("username1", Optional.of("password1")),
          TestCredential.create("username2", Optional.of("password2")),
          TestCredential.create("username3", Optional.of("password3")));
  private static final int BATCH_SIZE = 2;
  private CredentialTester tester;
  private WeakCredentialComposer composer;

  @Before
  public void setupComposer() {
    tester = mock(CredentialTester.class);
    when(tester.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());
    when(tester.batched()).thenReturn(true);
    composer = new WeakCredentialComposer(TEST_CREDENTIALS, tester, BATCH_SIZE);
  }

  @Test
  public void
      run_whenTesterDoesNotAccepterTargetOrService_testerAndProviderAreNotCalledAndReturnsEmptyList() {
    when(tester.canAccept(any())).thenReturn(false);
    composer.run(
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());

    verify(tester, never()).testValidCredentials(any(), any());
  }

  @Test
  public void run_whenTesterDoesAccepterTargetOrService_testerCalledWithBatchSize() {
    when(tester.canAccept(any())).thenReturn(true);
    composer.run(
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build());

    // First call with batch size.
    verify(tester)
        .testValidCredentials(
            any(),
            eq(
                ImmutableList.of(
                    TestCredential.create("username1", Optional.of("password1")),
                    TestCredential.create("username2", Optional.of("password2")))));
    // Second call with remaining values.
    verify(tester)
        .testValidCredentials(
            any(),
            eq(ImmutableList.of(TestCredential.create("username3", Optional.of("password3")))));
  }

  @Test
  public void run_whenOneMatchingCredentialIsFound_returnsListOfIdentifiedCredentials() {
    when(tester.canAccept(any())).thenReturn(true);
    when(tester.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of());

    ImmutableList<TestCredential> identifiedCredentials =
        composer.run(
            NetworkService.newBuilder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    assertThat(identifiedCredentials)
        .containsExactly(TestCredential.create("username1", Optional.of("password1")));
  }

  @Test
  public void run_whenMultipleMatchingCredentialIsFound_returnsListOfIdentifiedCredentials() {
    when(tester.canAccept(any())).thenReturn(true);
    when(tester.testValidCredentials(any(), any()))
        .thenReturn(ImmutableList.of(TestCredential.create("username1", Optional.of("password1"))))
        .thenReturn(ImmutableList.of(TestCredential.create("username3", Optional.of("password3"))));

    ImmutableList<TestCredential> identifiedCredentials =
        composer.run(
            NetworkService.newBuilder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 80))
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());

    assertThat(identifiedCredentials)
        .containsExactly(
            TestCredential.create("username1", Optional.of("password1")),
            TestCredential.create("username3", Optional.of("password3")));
  }
}
