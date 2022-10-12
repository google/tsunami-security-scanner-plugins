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
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PathParameterInjection}. */
@RunWith(JUnit4.class)
public final class PathParameterInjectionTest {
  private static final PathParameterInjection INJECTION_POINT = new PathParameterInjection();

  @Test
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForRoot() {
    HttpRequest exploitAtRoot =
        HttpRequest.get("https://google.com/../../../../etc/passwd").withEmptyHeaders().build();

    assertThat(
            INJECTION_POINT.injectPayload(
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                "../../../../etc/passwd"))
        .contains(exploitAtRoot);
  }

  @Test
  public void injectPayload_onRelativePathTraversalPayload_generatesExploitsForCurrentPath() {
    HttpRequest exploitAtCurrentPath =
        HttpRequest.get("https://google.com/path/to/../../../../etc/passwd")
            .withEmptyHeaders()
            .build();

    assertThat(
            INJECTION_POINT.injectPayload(
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                "../../../../etc/passwd"))
        .contains(exploitAtCurrentPath);
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
    Set<HttpRequest> requests = new HashSet<>();
    for (String target : targets) {
      requests.add(HttpRequest.get(target).withEmptyHeaders().build());
    }

    assertThat(
            INJECTION_POINT.injectPayload(
                HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                "../../../../etc/passwd"))
        .containsAtLeastElementsIn(requests);
  }

  @Test
  public void injectPayload_whenInjectionAtRoot_doesNotGenerateAdditionalExploitsAtCurrentPath() {
    assertThat(
            INJECTION_POINT
                .injectPayload(
                    HttpRequest.get("https://google.com").withEmptyHeaders().build(),
                    "../../../../etc/passwd")
                .size())
        .isLessThan(
            INJECTION_POINT
                .injectPayload(
                    HttpRequest.get("https://google.com/path/to/file").withEmptyHeaders().build(),
                    "../../../../etc/passwd")
                .size());
  }

  @Test
  public void injectPayload_whenInjectionAtRoot_ignoresTrailingSlash() {
    assertThat(
            INJECTION_POINT.injectPayload(
                HttpRequest.get("https://google.com").withEmptyHeaders().build(),
                "../../../../etc/passwd"))
        .containsExactlyElementsIn(
            INJECTION_POINT.injectPayload(
                HttpRequest.get("https://google.com/").withEmptyHeaders().build(),
                "../../../../etc/passwd"));
  }
}
