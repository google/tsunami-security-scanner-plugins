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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hive;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.sql.Connection;
import java.util.Optional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Tests for {@link HiveCredentialTester}. */
@RunWith(JUnit4.class)
public class HiveCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  private HiveCredentialTester tester;

  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("user", Optional.of("1234"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("root", Optional.of("pass"));

  @Before
  public void setup() {
    tester = new HiveCredentialTester(mockConnectionProvider);
  }

  @Test
  public void detect_weakCredExists_returnsWeakCred() throws Exception {
    when(mockConnectionProvider.getConnection(
            "jdbc:hive2://example.com:10000/default", "user", "1234"))
        .thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 10000))
            .setServiceName("snet-sensor-mgmt")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_weakCredsExist_returnsAllWeakCreds() throws Exception {
    when(mockConnectionProvider.getConnection(
            "jdbc:hive2://example.com:10000/default", "user", "1234"))
        .thenReturn(mockConnection);
    when(mockConnectionProvider.getConnection(
            "jdbc:hive2://example.com:10000/default", "root", "pass"))
        .thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 10000))
            .setServiceName("snet-sensor-mgmt")
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1, WEAK_CRED_2);
  }

  @Test
  public void detect_noWeakCred_returnsNoCred() throws Exception {
    when(mockConnectionProvider.getConnection(
            "jdbc:hive2://example.com:10000/default", "hardtoguess", "hardtoguess"))
        .thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 10000))
            .setServiceName("snet-sensor-mgmt")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .isEmpty();
  }

  @Test
  public void detect_hiveService_skips() throws Exception {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 10000))
            .setServiceName("snet-sensor-mgmt")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of()))
        .isEmpty();
    verifyNoInteractions(mockConnectionProvider);
  }
}
