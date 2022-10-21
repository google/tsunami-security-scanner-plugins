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

import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PathParameterInjection}. */
@RunWith(JUnit4.class)
public final class PathParameterInjectionTest {
  private static final PathParameterInjection INJECTION_POINT = new PathParameterInjection();

  private static final NetworkService MINIMAL_NETWORK_SERVICE =
      NetworkService.newBuilder().setServiceName("http").build();
  private static final String PAYLOAD = "../../../../etc/passwd";

  @Test
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForCurrentPath() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/" + PAYLOAD).withEmptyHeaders().build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                PAYLOAD))
        .contains(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE,
                exploitAtCurrentPath,
                PAYLOAD,
                PotentialExploit.Priority.LOW));
  }

  @Test
  public void injectPayload_whenInjectionAtRoot_doesGenerateExploitAtCurrentPath() {
    HttpRequest exploitAtRoot =
        HttpRequest.get("https://google.com/" + PAYLOAD).withEmptyHeaders().build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/").withEmptyHeaders().build(),
                PAYLOAD))
        .contains(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE, exploitAtRoot, PAYLOAD, PotentialExploit.Priority.LOW));
  }

  @Test
  public void injectPayload_whenPathSuffixRepresentsPath_assignsHighPriority() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/" + PAYLOAD).withEmptyHeaders().build();

    ImmutableSet<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE,
            HttpRequest.get("https://google.com/path/to/a%2Fb").withEmptyHeaders().build(),
            PAYLOAD);
    PotentialExploit generatedExploit =
        exploits.stream()
            .filter(exploit -> exploit.request().equals(exploitAtCurrentPath))
            .findFirst()
            .get();

    assertThat(generatedExploit.priority()).isEqualTo(PotentialExploit.Priority.HIGH);
  }

  @Test
  public void injectPayload_whenPathEndsWithFileExtension_assignsMediumPriority() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/" + PAYLOAD).withEmptyHeaders().build();

    ImmutableSet<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE,
            HttpRequest.get("https://google.com/path/to/file.jpg").withEmptyHeaders().build(),
            PAYLOAD);
    PotentialExploit generatedExploit =
        exploits.stream()
            .filter(exploit -> exploit.request().equals(exploitAtCurrentPath))
            .findFirst()
            .get();

    assertThat(generatedExploit.priority()).isEqualTo(PotentialExploit.Priority.MEDIUM);
  }

  @Test
  public void injectPayload_whenPathContainsCommonSubPath_assignsMediumPriority() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/admin/" + PAYLOAD).withEmptyHeaders().build();

    ImmutableSet<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE,
            HttpRequest.get("https://google.com/path/to/admin/file").withEmptyHeaders().build(),
            PAYLOAD);
    PotentialExploit generatedExploit =
        exploits.stream()
            .filter(exploit -> exploit.request().equals(exploitAtCurrentPath))
            .findFirst()
            .get();

    assertThat(generatedExploit.priority()).isEqualTo(PotentialExploit.Priority.MEDIUM);
  }

  @Test
  public void injectPayload_whenPathContainsUncommonSubPath_assignsLowPriority() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/notadmin/" + PAYLOAD)
            .withEmptyHeaders()
            .build();

    ImmutableSet<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE,
            HttpRequest.get("https://google.com/path/to/notadmin/file").withEmptyHeaders().build(),
            PAYLOAD);
    PotentialExploit generatedExploit =
        exploits.stream()
            .filter(exploit -> exploit.request().equals(exploitAtCurrentPath))
            .findFirst()
            .get();

    assertThat(generatedExploit.priority()).isEqualTo(PotentialExploit.Priority.LOW);
  }
}
