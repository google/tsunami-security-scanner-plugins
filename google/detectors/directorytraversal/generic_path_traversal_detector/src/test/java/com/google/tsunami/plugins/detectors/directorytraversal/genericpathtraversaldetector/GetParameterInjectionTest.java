/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.Truth8;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link GetParameterInjection}. */
@RunWith(JUnit4.class)
public final class GetParameterInjectionTest {
  private static final GetParameterInjection INJECTION_POINT = new GetParameterInjection();

  private static final HttpRequest REQUEST_WITHOUT_GET_PARAMETERS =
      HttpRequest.get("https://google.com").withEmptyHeaders().build();
  private static final HttpRequest REQUEST_WITH_GET_PARAMETERS =
      HttpRequest.get("https://google.com?key=value&other=test").withEmptyHeaders().build();
  private static final NetworkService MINIMAL_NETWORK_SERVICE =
      NetworkService.newBuilder().setServiceName("http").build();
  private static final String PAYLOAD = "../../../../etc/passwd";

  @Test
  public void injectPayload_onRelativePathTraversalPayloadWithGetParameters_generatesExploits() {
    ImmutableList<PotentialExploit> exploitsWithPayloadInGetParameters =
        ImmutableList.of(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com?key=" + PAYLOAD + "&other=test")
                    .withEmptyHeaders()
                    .build(),
                PAYLOAD,
                PotentialExploit.Priority.LOW),
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com?key=value&other=" + PAYLOAD)
                    .withEmptyHeaders()
                    .build(),
                PAYLOAD,
                PotentialExploit.Priority.LOW));

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE, REQUEST_WITH_GET_PARAMETERS, PAYLOAD))
        .containsAtLeastElementsIn(exploitsWithPayloadInGetParameters);
  }

  @Test
  public void
      injectPayload_whenGetParameterHasFileExtensionAndPrefix_generatesExploitsWithFileExtensionAndPrefix() {
    HttpRequest requestWIthFileExtensionAndPrefix =
        HttpRequest.get("https://google.com?key=value.jpg&other=resources/test")
            .withEmptyHeaders()
            .build();
    ImmutableList<PotentialExploit> exploitsWithFileExtensionAndPrefix =
        ImmutableList.of(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get(
                        "https://google.com?key=" + PAYLOAD + "%00.jpg&other=resources/test")
                    .withEmptyHeaders()
                    .build(),
                PAYLOAD,
                PotentialExploit.Priority.LOW),
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com?key=value.jpg&other=resources/" + PAYLOAD)
                    .withEmptyHeaders()
                    .build(),
                PAYLOAD,
                PotentialExploit.Priority.LOW));

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE, requestWIthFileExtensionAndPrefix, PAYLOAD))
        .containsAtLeastElementsIn(exploitsWithFileExtensionAndPrefix);
  }

  @Test
  public void
      injectPayload_onRelativePathTraversalPayloadWithoutGetParameters_generatesNoExploits() {
    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE, REQUEST_WITHOUT_GET_PARAMETERS, PAYLOAD))
        .isEmpty();
  }

  @Test
  public void injectPayload_whenPromisingParameterName_assignsHighPriority() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?file=test").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    for (PotentialExploit exploit : exploits) {
      assertThat(exploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
    }
  }

  @Test
  public void
      injectPayload_whenPromisingParameterNameIsSnakeCase_normalizesValueAndAssignsHighPriority() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?file_name=test").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    for (PotentialExploit exploit : exploits) {
      assertThat(exploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
    }
  }

  @Test
  public void injectPayload_whenPromisingParameterName_assignsPriorityOnlyToPromisingParameter() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?file=test&notfile=nottest").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    Truth8.assertThat(exploits.stream().map(PotentialExploit::priority))
        .containsExactly(PotentialExploit.Priority.LOW, PotentialExploit.Priority.HIGH);
  }

  @Test
  public void injectPayload_whenParameterValueRepresentsPath_assignsHighPriority() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?key=path/to/file").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    for (PotentialExploit exploit : exploits) {
      assertThat(exploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
    }
  }

  @Test
  public void injectPayload_whenParameterValueRepresentsEncodedPath_assignsHighPriority() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?key=path%2Fto%2ffile").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    for (PotentialExploit exploit : exploits) {
      assertThat(exploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
    }
  }

  @Test
  public void injectPayload_whenParameterValueHasFileExtension_assignsHighPriority() {
    HttpRequest requestWithPromisingParameterName =
        HttpRequest.get("https://google.com?key=img.jpg").withEmptyHeaders().build();
    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE, requestWithPromisingParameterName, PAYLOAD);

    for (PotentialExploit exploit : exploits) {
      assertThat(exploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
    }
  }
}
