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
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForRoot() {
    HttpRequest exploitAtRoot =
        HttpRequest.get("https://google.com/../../../../etc/passwd").withEmptyHeaders().build();

    assertThat(
            INJECTION_POINT.injectPayload(
                MINIMAL_NETWORK_SERVICE,
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                PAYLOAD))
        .contains(
            PotentialExploit.create(
                MINIMAL_NETWORK_SERVICE, exploitAtRoot, PAYLOAD, PotentialExploit.Priority.LOW));
  }

  @Test
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForCurrentPath() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/../../../../etc/passwd")
            .withEmptyHeaders()
            .build();

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
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForCommonPaths() {
    ImmutableSet<String> targets =
        ImmutableSet.of(
            // go/keep-sorted start
            "https://google.com/admin/../../../../etc/passwd",
            "https://google.com/album/../../../../etc/passwd",
            "https://google.com/app/../../../../etc/passwd",
            "https://google.com/assets/../../../../etc/passwd",
            "https://google.com/bin/../../../../etc/passwd",
            "https://google.com/console/../../../../etc/passwd",
            "https://google.com/css/../../../../etc/passwd",
            "https://google.com/demo/../../../../etc/passwd",
            "https://google.com/doc/../../../../etc/passwd",
            "https://google.com/eqx/../../../../etc/passwd",
            "https://google.com/files/../../../../etc/passwd",
            "https://google.com/fs/../../../../etc/passwd",
            "https://google.com/html/../../../../etc/passwd",
            "https://google.com/img-sys/../../../../etc/passwd",
            "https://google.com/jquery_ui/../../../../etc/passwd",
            "https://google.com/js/../../../../etc/passwd",
            "https://google.com/media/../../../../etc/passwd",
            "https://google.com/public/../../../../etc/passwd",
            "https://google.com/scripts/../../../../etc/passwd",
            "https://google.com/static/../../../../etc/passwd",
            "https://google.com/tmp/../../../../etc/passwd",
            "https://google.com/upload/../../../../etc/passwd",
            "https://google.com/xls/../../../../etc/passwd"
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
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                PAYLOAD))
        .containsAtLeastElementsIn(exploits);
  }

  @Test
  public void injectPayload_whenInjectionAtRoot_doesNotGenerateAdditionalExploitsAtCurrentPath() {
    assertThat(
            INJECTION_POINT
                .injectPayload(
                    MINIMAL_NETWORK_SERVICE,
                    HttpRequest.get("https://google.com").withEmptyHeaders().build(),
                    PAYLOAD)
                .size())
        .isLessThan(
            INJECTION_POINT
                .injectPayload(
                    MINIMAL_NETWORK_SERVICE,
                    HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                    PAYLOAD)
                .size());
  }

  @Test
  public void injectPayload_whenInjectionAtRoot_ignoresTrailingSlash() {
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
}
