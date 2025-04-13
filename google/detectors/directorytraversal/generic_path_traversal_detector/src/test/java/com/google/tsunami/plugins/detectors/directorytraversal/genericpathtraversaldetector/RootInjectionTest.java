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
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RootInjection}. */
@RunWith(JUnit4.class)
public final class RootInjectionTest {
  private static final RootInjection INJECTION_POINT = new RootInjection();

  private static final NetworkService MINIMAL_NETWORK_SERVICE =
      NetworkService.newBuilder().setServiceName("http").build();
  private static final String PAYLOAD = "../../../../etc/passwd";

  @Test
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForRoot() {
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
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForCommonPaths() {
    ImmutableSet<String> targets =
        ImmutableSet.of(
            // go/keep-sorted start
            "https://google.com/admin/" + PAYLOAD,
            "https://google.com/album/" + PAYLOAD,
            "https://google.com/app/" + PAYLOAD,
            "https://google.com/assets/" + PAYLOAD,
            "https://google.com/bin/" + PAYLOAD,
            "https://google.com/console/" + PAYLOAD,
            "https://google.com/css/" + PAYLOAD,
            "https://google.com/demo/" + PAYLOAD,
            "https://google.com/doc/" + PAYLOAD,
            "https://google.com/eqx/" + PAYLOAD,
            "https://google.com/files/" + PAYLOAD,
            "https://google.com/fs/" + PAYLOAD,
            "https://google.com/html/" + PAYLOAD,
            "https://google.com/img-sys/" + PAYLOAD,
            "https://google.com/jquery_ui/" + PAYLOAD,
            "https://google.com/js/" + PAYLOAD,
            "https://google.com/media/" + PAYLOAD,
            "https://google.com/public/" + PAYLOAD,
            "https://google.com/scripts/" + PAYLOAD,
            "https://google.com/static/" + PAYLOAD,
            "https://google.com/tmp/" + PAYLOAD,
            "https://google.com/upload/" + PAYLOAD,
            "https://google.com/xls/" + PAYLOAD
            // go/keep-sorted end
            );
    ImmutableSet.Builder<PotentialExploit> builder = ImmutableSet.builder();
    for (String target : targets) {
      builder.add(
          PotentialExploit.create(
              MINIMAL_NETWORK_SERVICE,
              HttpRequest.get(target).withEmptyHeaders().build(),
              PAYLOAD,
              PotentialExploit.Priority.LOW));
    }
    ImmutableSet<PotentialExploit> exploits = builder.build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/").withEmptyHeaders().build(),
                PAYLOAD))
        .containsAtLeastElementsIn(exploits);
  }

  @Test
  public void injectPayload_givenIpAddressAndNonStandardPort_generatesExploitsForRoot() {
    HttpRequest exploitAtRoot =
        HttpRequest.get("https://8.8.8.8:42/" + PAYLOAD).withEmptyHeaders().build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://8.8.8.8:42/").withEmptyHeaders().build(),
                PAYLOAD))
        .contains(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE, exploitAtRoot, PAYLOAD, PotentialExploit.Priority.LOW));
  }

  @Test
  public void injectPayload_givenIpAddressAndNonStandardPort_generatesExploitsForCommonPaths() {
    ImmutableSet<String> targets =
        ImmutableSet.of(
            // go/keep-sorted start
            "https://8.8.8.8:42/admin/" + PAYLOAD,
            "https://8.8.8.8:42/album/" + PAYLOAD,
            "https://8.8.8.8:42/app/" + PAYLOAD,
            "https://8.8.8.8:42/assets/" + PAYLOAD,
            "https://8.8.8.8:42/bin/" + PAYLOAD,
            "https://8.8.8.8:42/console/" + PAYLOAD,
            "https://8.8.8.8:42/css/" + PAYLOAD,
            "https://8.8.8.8:42/demo/" + PAYLOAD,
            "https://8.8.8.8:42/doc/" + PAYLOAD,
            "https://8.8.8.8:42/eqx/" + PAYLOAD,
            "https://8.8.8.8:42/files/" + PAYLOAD,
            "https://8.8.8.8:42/fs/" + PAYLOAD,
            "https://8.8.8.8:42/html/" + PAYLOAD,
            "https://8.8.8.8:42/img-sys/" + PAYLOAD,
            "https://8.8.8.8:42/jquery_ui/" + PAYLOAD,
            "https://8.8.8.8:42/js/" + PAYLOAD,
            "https://8.8.8.8:42/media/" + PAYLOAD,
            "https://8.8.8.8:42/public/" + PAYLOAD,
            "https://8.8.8.8:42/scripts/" + PAYLOAD,
            "https://8.8.8.8:42/static/" + PAYLOAD,
            "https://8.8.8.8:42/tmp/" + PAYLOAD,
            "https://8.8.8.8:42/upload/" + PAYLOAD,
            "https://8.8.8.8:42/xls/" + PAYLOAD
            // go/keep-sorted end
            );
    ImmutableSet.Builder<PotentialExploit> builder = ImmutableSet.builder();
    for (String target : targets) {
      builder.add(
          PotentialExploit.create(
              MINIMAL_NETWORK_SERVICE,
              HttpRequest.get(target).withEmptyHeaders().build(),
              PAYLOAD,
              PotentialExploit.Priority.LOW));
    }
    ImmutableSet<PotentialExploit> exploits = builder.build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://8.8.8.8:42/").withEmptyHeaders().build(),
                PAYLOAD))
        .containsAtLeastElementsIn(exploits);
  }

  @Test
  public void injectPayload_whenTargetIsNotRoot_doesNotGenerateExploits() {
    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                PAYLOAD))
        .isEmpty();
  }

  @Test
  public void injectPayload_always_ignoresTrailingSlash() {
    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com").withEmptyHeaders().build(),
                PAYLOAD))
        .containsExactlyElementsIn(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/").withEmptyHeaders().build(),
                PAYLOAD));
  }

  @Test
  public void injectPayload_always_assignsLowPriority() {
    HttpRequest exploitAtRoot =
        HttpRequest.get("https://google.com/" + PAYLOAD).withEmptyHeaders().build();

    ImmutableList<PotentialExploit> exploits =
        INJECTION_POINT.injectPayload(
            MINIMAL_NETWORK_SERVICE,
            HttpRequest.get("https://google.com/").withEmptyHeaders().build(),
            PAYLOAD);
    PotentialExploit generatedExploit =
        exploits.stream()
            .filter(exploit -> exploit.request().equals(exploitAtRoot))
            .findFirst()
            .get();

    assertThat(generatedExploit.priority()).isEqualTo(PotentialExploit.Priority.LOW);
  }
}
